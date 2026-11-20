"""Generate an appendable, uncompressed OCI diff layer between two images.

The two inputs are single-manifest OCI Image Layout tars for the *same*
platform.  Both go through exactly the same verification as ``/unpack``
(blob presence/size/SHA-256 plus config ``diff_ids``).  Their layers are
unpacked into per-request rootfs trees, which are then compared.

The produced layer tar:

* is an **uncompressed** OCI layer tar (PAX), ready to be appended on top
  of the old image;
* expresses deletions with OCI whiteouts (``.wh.<name>``);
* supports swapping directories and files (a whiteout followed by the new
  entry -- whiteouts only remove lower-layer state, so the new entry
  survives);
* leaves fully unchanged regular files and unchanged hardlink groups in
  the lower layers (no entry is emitted);
* can split or merge hardlink groups even when the file bytes are
  identical, because hardlink grouping is compared independently of
  content;
* streams file content in fixed-size blocks (whole files are never loaded
  into memory).

Before the layer is returned it is verified twice:

1. a logical in-memory overlay simulation (authoritative for mode,
   numeric UID/GID, second-resolution mtime, symlink text and hardlink
   grouping, none of which need privileges);
2. a physical trial: the layer is really unpacked on top of a fresh copy
   of the old image using the same code path as ``/unpack``.

Only when the trial result equals the target tree on every checked
attribute is the layer tar handed back; any failure fails the request.

Only regular files, directories, symlinks and hardlinks pointing at
regular files are accepted.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tarfile
from dataclasses import dataclass, field

from .unpacker import (
    CHUNK,
    OPAQUE_MARKER,
    WHITEOUT_PREFIX,
    UnpackError,
    _apply_deferred_dir_meta,
    _normalize_archive_name,
    apply_layer,
    extract_layout,
    verify_layout,
)

# Entry kinds used inside the diff plan.
KIND_WHITEOUT = "whiteout"
KIND_DIR = "dir"
KIND_FILE = "file"
KIND_SYMLINK = "symlink"
KIND_HARDLINK = "hardlink"


class DifferError(Exception):
    """Any invalid input or failed verification of a diff request."""


# ---------------------------------------------------------------------------
# filesystem tree model
# ---------------------------------------------------------------------------


@dataclass
class Node:
    """One filesystem entry, compared between the old and new tree."""

    type: str  # "dir" | "file" | "symlink"
    mode: int
    uid: int
    gid: int
    mtime: int
    size: int = 0
    sha256: str = ""  # regular files only
    linkname: str = ""  # symlinks only


@dataclass
class Tree:
    rootfs: str
    nodes: dict = field(default_factory=dict)  # relpath -> Node
    # synthetic inode token -> sorted member relpaths (regular files only)
    groups: dict = field(default_factory=dict)


def _parent(relpath):
    idx = relpath.rfind("/")
    return relpath[:idx] if idx >= 0 else ""


def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(CHUNK), b""):
            h.update(blk)
    return h.hexdigest()


def _hash_stream(src):
    h = hashlib.sha256()
    for blk in iter(lambda: src.read(CHUNK), b""):
        h.update(blk)
    return h.hexdigest()


def build_tree(layer_tars, rootfs):
    """Build the logical file tree straight from the layer tar headers.

    Tar metadata (mode, numeric UID/GID, second mtime, symlink text and
    LNKTYPE grouping) is the authoritative source, so the result does not
    depend on whether the host process is allowed to ``chown``.  Whiteouts
    and opaque markers are applied with exactly the same semantics as
    :func:`unpacker.apply_layer`: deletions affect lower layers only and
    are computed per layer before additions.  File content is hashed
    block-by-block from the tar stream.

    Only regular files, directories, symlinks and hardlinks to regular
    files are accepted; whiteout-style names in visible content are
    rejected.
    """
    state = {}  # relpath -> dict(type, mode, uid, gid, mtime, size, sha, link, token)
    token_seq = 0

    for layer_index, tar_path in enumerate(layer_tars):
        try:
            tf = tarfile.open(tar_path, "r:")
        except (tarfile.TarError, OSError) as e:
            raise UnpackError(f"layer {layer_index}: cannot read layer tar: {e}")
        with tf:
            try:
                members = tf.getmembers()
            except tarfile.TarError as e:
                raise UnpackError(f"layer {layer_index}: corrupt layer tar: {e}")

            deletions, opaque_dirs, additions = [], [], []
            for m in members:
                parts = _normalize_archive_name(m.name, "layer entry")
                if not parts:
                    continue
                base = parts[-1]
                if base == OPAQUE_MARKER:
                    opaque_dirs.append(parts[:-1])
                elif base.startswith(WHITEOUT_PREFIX):
                    target = base[len(WHITEOUT_PREFIX):]
                    if not target:
                        raise UnpackError(f"layer {layer_index}: invalid whiteout")
                    deletions.append("/".join(parts[:-1] + [target]))
                else:
                    additions.append((m, "/".join(parts)))

            # Phase 1: lower-state deletions only.
            for path in deletions:
                prefix = path + "/"
                for p in [p for p in state if p == path or p.startswith(prefix)]:
                    del state[p]
            for parts in opaque_dirs:
                d = "/".join(parts)
                prefix = d + "/" if d else ""
                for p in [p for p in state if p.startswith(prefix)]:
                    del state[p]

            # Phase 2: additions in tar order.
            for m, path in additions:
                base = path.rsplit("/", 1)[-1]
                if base.startswith(WHITEOUT_PREFIX):
                    raise DifferError(
                        f"unsupported whiteout-style entry name in image: {path!r}"
                    )
                meta = (
                    stat.S_IMODE(m.mode),
                    m.uid,
                    m.gid,
                    int(m.mtime),
                )
                if m.isdir():
                    if path in state and state[path]["type"] != "dir":
                        del state[path]
                    state[path] = {
                        "type": "dir",
                        "mode": meta[0],
                        "uid": meta[1],
                        "gid": meta[2],
                        "mtime": meta[3],
                        "size": 0,
                        "sha256": "",
                        "linkname": "",
                        "token": None,
                    }
                elif m.isreg():
                    src = tf.extractfile(m)
                    if src is None:
                        raise UnpackError(
                            f"layer {layer_index}: cannot read file entry {path!r}"
                        )
                    digest = _hash_stream(src)
                    token_seq += 1
                    if path in state and state[path]["type"] != "dir":
                        del state[path]
                    state[path] = {
                        "type": "file",
                        "mode": meta[0],
                        "uid": meta[1],
                        "gid": meta[2],
                        "mtime": meta[3],
                        "size": m.size,
                        "sha256": digest,
                        "linkname": "",
                        "token": f"t{token_seq}",
                    }
                elif m.issym():
                    if not m.linkname or "\x00" in m.linkname:
                        raise DifferError(f"invalid symlink target at {path!r}")
                    if path in state and state[path]["type"] != "dir":
                        del state[path]
                    state[path] = {
                        "type": "symlink",
                        "mode": meta[0],
                        "uid": meta[1],
                        "gid": meta[2],
                        "mtime": meta[3],
                        "size": 0,
                        "sha256": "",
                        "linkname": m.linkname,
                        "token": None,
                    }
                elif m.islnk():
                    tparts = _normalize_archive_name(
                        m.linkname, f"hardlink target of {path!r}"
                    )
                    target = "/".join(tparts)
                    if target not in state or state[target]["type"] != "file":
                        raise DifferError(
                            f"hardlink {path!r}: target {m.linkname!r} is not a "
                            f"regular file present in lower layers"
                        )
                    if path in state and state[path]["type"] != "dir":
                        del state[path]
                    copy = dict(state[target])
                    copy["mode"], copy["uid"], copy["gid"], copy["mtime"] = meta
                    state[path] = copy
                else:
                    raise DifferError(
                        f"unsupported file type in image (only regular files, "
                        f"directories, symlinks and hardlinks are allowed): "
                        f"{path!r}"
                    )

    tree = Tree(rootfs=rootfs)
    groups = {}
    for path, st_ in sorted(state.items()):
        tree.nodes[path] = Node(
            st_["type"],
            st_["mode"],
            st_["uid"],
            st_["gid"],
            st_["mtime"],
            size=st_["size"],
            sha256=st_["sha256"],
            linkname=st_["linkname"],
        )
        if st_["type"] == "file":
            groups.setdefault(st_["token"], []).append(path)
    tree.groups = {token: sorted(members) for token, members in groups.items()}
    return tree


# ---------------------------------------------------------------------------
# diff plan
# ---------------------------------------------------------------------------


@dataclass
class Entry:
    kind: str
    path: str
    node: Node = None
    linkname: str = ""  # hardlink target path


def _same_file_meta(a, b):
    return (a.mode, a.uid, a.gid, a.mtime) == (b.mode, b.uid, b.gid, b.mtime)


def _mark_ancestors(changed_dirs, path):
    anc = _parent(path)
    while anc:
        changed_dirs.add(anc)
        anc = _parent(anc)


def compute_diff(old, new):
    """Compare two :class:`Tree` objects and return ordered diff entries."""
    old_nodes, new_nodes = old.nodes, new.nodes
    # Only *multi-member* groups are hardlink groups; singleton tokens are
    # just ordinary independent files.
    old_by_path_group = {}
    for token, members in old.groups.items():
        if len(members) > 1:
            for p in members:
                old_by_path_group[p] = token
    new_by_path_group = {}
    for token, members in new.groups.items():
        if len(members) > 1:
            for p in members:
                new_by_path_group[p] = token

    whiteouts = []
    changed_dirs = set()
    # Paths that keep their name but change their entry type: the new entry
    # must always be emitted after the whiteout.
    swapped = set()

    # Pass 1: deletions and type swaps need a whiteout first.
    for path, on in old_nodes.items():
        nn = new_nodes.get(path)
        if nn is None or nn.type != on.type:
            whiteouts.append(path)
            _mark_ancestors(changed_dirs, path)
            if nn is not None:
                swapped.add(path)

    # A whiteout on a directory already removes the whole lower subtree, so
    # whiteouts on paths beneath it are redundant and can be dropped.
    removed_dirs = sorted(
        [p for p in whiteouts if old_nodes[p].type == "dir"],
        key=lambda p: p.count("/"),
    )

    def _under_removed_dir(path):
        for d in removed_dirs:
            if path.startswith(d + "/"):
                return True
        return False

    whiteouts = [p for p in whiteouts if not _under_removed_dir(p)]

    # New paths (of any type) touch their parent directories.
    for path in new_nodes:
        if path not in old_nodes:
            _mark_ancestors(changed_dirs, path)

    file_entries = []
    symlink_entries = []
    hardlink_entries = []
    emitted_groups = set()

    # Pass 2: symlinks.
    for path, nn in sorted(new_nodes.items()):
        if nn.type != "symlink":
            continue
        on = old_nodes.get(path)
        if (
            path in swapped
            or on is None
            or on.type != "symlink"
            or on.linkname != nn.linkname
            or not _same_file_meta(on, nn)
        ):
            symlink_entries.append(Entry(KIND_SYMLINK, path, nn))

    # Pass 3: regular files. Hardlink groups are handled as a whole so that
    # split/merge decisions never depend on byte equality alone.
    for path, nn in sorted(new_nodes.items()):
        if nn.type != "file" or path in new_by_path_group:
            continue  # linked files are handled with their group below
        on = old_nodes.get(path)
        unchanged = (
            path not in swapped
            and on is not None
            and on.type == "file"
            and path not in old_by_path_group
            and on.sha256 == nn.sha256
            and _same_file_meta(on, nn)
        )
        if not unchanged:
            file_entries.append(Entry(KIND_FILE, path, nn))

    for token, members in sorted(
        (kv for kv in new.groups.items() if len(kv[1]) > 1),
        key=lambda kv: kv[1][0],
    ):
        if token in emitted_groups:
            continue
        emitted_groups.add(token)
        nn0 = new_nodes[members[0]]

        old_token = next(
            (old_by_path_group[p] for p in members if p in old_by_path_group),
            None,
        )
        old_members = old.groups.get(old_token, []) if old_token is not None else []
        group_unchanged = (
            not any(p in swapped for p in members)
            and bool(old_members)
            and set(old_members) == set(members)
            and all(
                old_nodes[p].type == "file"
                and old_nodes[p].sha256 == nn0.sha256
                and _same_file_meta(old_nodes[p], new_nodes[p])
                for p in members
            )
        )
        if group_unchanged:
            continue

        # Pick an anchor. Reusing a lower-layer singleton with identical
        # bytes+meta costs no content; any old hardlink group whose member
        # set is not fully carried over cannot be reused (that would keep
        # the old group linked). Otherwise emit the first member in full.
        anchor = None
        if not any(p in swapped for p in members):
            for p in members:
                on = old_nodes.get(p)
                if (
                    on is not None
                    and on.type == "file"
                    and p not in old_by_path_group
                    and on.sha256 == nn0.sha256
                    and _same_file_meta(on, nn0)
                ):
                    anchor = p
                    break
        if anchor is None:
            anchor = members[0]
            file_entries.append(Entry(KIND_FILE, anchor, nn0))
        for p in members:
            if p == anchor:
                continue
            hardlink_entries.append(
                Entry(KIND_HARDLINK, p, new_nodes[p], linkname=anchor)
            )

    # Any emitted addition changes its parent directory's mtime on overlay,
    # so the target directory metadata has to be replayed as well.
    for e in file_entries + symlink_entries + hardlink_entries:
        _mark_ancestors(changed_dirs, e.path)

    # Pass 4: directories (after all changed paths are known).
    dir_entries = []
    for path, nn in sorted(new_nodes.items()):
        if nn.type != "dir":
            continue
        on = old_nodes.get(path)
        if (
            path in swapped
            or path not in old_nodes
            or path in changed_dirs
            or on.type != "dir"
            or not _same_file_meta(on, nn)
        ):
            dir_entries.append(Entry(KIND_DIR, path, nn))

    file_entries.sort(key=lambda e: e.path)
    hardlink_entries.sort(key=lambda e: e.path)

    ordered = (
        [Entry(KIND_WHITEOUT, p) for p in sorted(whiteouts)]
        + dir_entries
        + file_entries
        + symlink_entries
        + hardlink_entries
    )
    return ordered


# ---------------------------------------------------------------------------
# layer tar output (streamed, uncompressed)
# ---------------------------------------------------------------------------


def _tarinfo(entry):
    node = entry.node
    if entry.kind == KIND_WHITEOUT:
        parent = _parent(entry.path)
        base = entry.path.rsplit("/", 1)[-1]
        ti = tarfile.TarInfo(
            f"{parent}/.wh.{base}" if parent else f".wh.{base}"
        )
        ti.type = tarfile.REGTYPE
        ti.size = 0
        ti.mode = 0o000
        ti.mtime = 0
        ti.uid = ti.gid = 0
        return ti
    ti = tarfile.TarInfo(entry.path)
    ti.mode = node.mode
    ti.mtime = node.mtime
    ti.uid = node.uid
    ti.gid = node.gid
    if entry.kind == KIND_DIR:
        ti.type = tarfile.DIRTYPE
    elif entry.kind == KIND_FILE:
        ti.type = tarfile.REGTYPE
        ti.size = node.size
    elif entry.kind == KIND_SYMLINK:
        ti.type = tarfile.SYMTYPE
        ti.linkname = node.linkname
    elif entry.kind == KIND_HARDLINK:
        ti.type = tarfile.LNKTYPE
        ti.linkname = entry.linkname
    else:  # pragma: no cover - defensive
        raise DifferError(f"internal error: unknown entry kind {entry.kind}")
    return ti


def build_layer_tar(entries, new_rootfs, out_path):
    tmp = out_path + ".tmp"
    with tarfile.open(tmp, "w", format=tarfile.PAX_FORMAT) as tf:
        for entry in entries:
            ti = _tarinfo(entry)
            if entry.kind == KIND_FILE:
                with open(os.path.join(new_rootfs, entry.path), "rb") as f:
                    tf.addfile(ti, f)  # tarfile reads in tarfile.copyfileobj blocks
            else:
                tf.addfile(ti)
    os.replace(tmp, out_path)
    return out_path


# ---------------------------------------------------------------------------
# logical overlay simulation (privilege-independent, authoritative)
# ---------------------------------------------------------------------------


def _state_node(node, token):
    """Mutable in-memory overlay state for one path."""
    return {
        "type": node.type,
        "mode": node.mode,
        "uid": node.uid,
        "gid": node.gid,
        "mtime": node.mtime,
        "size": node.size,
        "sha256": node.sha256,
        "linkname": node.linkname,
        "token": token,
    }


def _remove_path(state, path):
    """Remove *path* and everything below it from the overlay state."""
    prefix = path + "/"
    for p in [p for p in state if p == path or p.startswith(prefix)]:
        del state[p]


def simulate_layer(diff_tar, old, new):
    """Apply *diff_tar* to an in-memory copy of *old*, then compare to *new*.

    Raises :class:`DifferError` on the first discrepancy.
    """
    try:
        tf = tarfile.open(diff_tar, "r:")
    except (tarfile.TarError, OSError) as e:
        raise DifferError(f"trial: generated layer is not a readable tar: {e}")

    state = {}
    token_seq = 0
    with tf:
        try:
            members = tf.getmembers()
        except tarfile.TarError as e:
            raise DifferError(f"trial: corrupt generated layer tar: {e}")

        deletions = []
        opaque_dirs = []
        additions = []
        for m in members:
            parts = _normalize_archive_name(m.name, "generated layer entry")
            if not parts:
                continue
            base = parts[-1]
            if base == OPAQUE_MARKER:
                opaque_dirs.append(parts[:-1])
            elif base.startswith(WHITEOUT_PREFIX):
                target = base[len(WHITEOUT_PREFIX):]
                if not target:
                    raise DifferError("trial: invalid whiteout in generated layer")
                deletions.append("/".join(parts[:-1] + [target]))
            else:
                additions.append((m, "/".join(parts)))
        # Seed the state from the old tree: every regular file gets its own
        # inode token, except members of a real hardlink group which share one.
        for path, node in old.nodes.items():
            if node.type == "file":
                token = next(
                    (
                        tok
                        for tok, members in old.groups.items()
                        if path in members
                    ),
                    None,
                )
                if token is None:
                    token_seq += 1
                    token = f"s{token_seq}"
            else:
                token = None
            state[path] = _state_node(node, token)

        # Phase 1: whiteouts / opaque markers (lower state only).
        for path in deletions:
            _remove_path(state, path)
        for parts in opaque_dirs:
            d = "/".join(parts)
            prefix = d + "/" if d else ""
            for p in [p for p in state if p.startswith(prefix)]:
                del state[p]

        # Phase 2: additions in tar order.
        for m, path in additions:
            if m.isdir():
                # A directory entry overlays metadata only: lower-layer
                # children must survive (mirrors apply_layer's makedirs).
                if path in state and state[path]["type"] != "dir":
                    del state[path]
                state[path] = {
                    "type": "dir",
                    "mode": stat.S_IMODE(m.mode),
                    "uid": m.uid,
                    "gid": m.gid,
                    "mtime": int(m.mtime),
                    "size": 0,
                    "sha256": "",
                    "linkname": "",
                    "token": None,
                }
            elif m.isreg():
                src = tf.extractfile(m)
                if src is None:
                    raise DifferError(f"trial: cannot read layer entry {path!r}")
                h = hashlib.sha256()
                for blk in iter(lambda: src.read(CHUNK), b""):
                    h.update(blk)
                token_seq += 1
                _remove_path(state, path)
                state[path] = {
                    "type": "file",
                    "mode": stat.S_IMODE(m.mode),
                    "uid": m.uid,
                    "gid": m.gid,
                    "mtime": int(m.mtime),
                    "size": m.size,
                    "sha256": h.hexdigest(),
                    "linkname": "",
                    "token": f"s{token_seq}",
                }
            elif m.issym():
                _remove_path(state, path)
                state[path] = {
                    "type": "symlink",
                    "mode": stat.S_IMODE(m.mode),
                    "uid": m.uid,
                    "gid": m.gid,
                    "mtime": int(m.mtime),
                    "size": 0,
                    "sha256": "",
                    "linkname": m.linkname,
                    "token": None,
                }
            elif m.islnk():
                if m.linkname not in state:
                    raise DifferError(
                        f"trial: hardlink {path!r} target {m.linkname!r} missing"
                    )
                target_st = state[m.linkname]
                if target_st["type"] != "file":
                    raise DifferError(
                        f"trial: hardlink {path!r} target {m.linkname!r} is not "
                        f"a regular file"
                    )
                _remove_path(state, path)
                copy = dict(target_st)
                copy["mode"] = stat.S_IMODE(m.mode)
                copy["uid"] = m.uid
                copy["gid"] = m.gid
                copy["mtime"] = int(m.mtime)
                state[path] = copy
            else:
                raise DifferError(
                    f"trial: unsupported entry type {m.type!r} in generated layer"
                )

    _compare_state_to_target(state, new)


def _compare_state_to_target(state, new):
    if set(state) != set(new.nodes):
        missing = sorted(set(new.nodes) - set(state))
        extra = sorted(set(state) - set(new.nodes))
        raise DifferError(
            f"trial: path set mismatch (missing={missing[:5]}, extra={extra[:5]})"
        )
    for path, want in sorted(new.nodes.items()):
        got = state[path]
        if got["type"] != want.type:
            raise DifferError(
                f"trial: type mismatch at {path!r}: "
                f"want {want.type}, got {got['type']}"
            )
        for attr, label in (
            ("mode", "mode"),
            ("uid", "UID"),
            ("gid", "GID"),
            ("mtime", "mtime"),
        ):
            if got[attr] != getattr(want, attr):
                raise DifferError(
                    f"trial: {label} mismatch at {path!r}: "
                    f"want {getattr(want, attr)}, got {got[attr]}"
                )
        if want.type == "file":
            if got["size"] != want.size or got["sha256"] != want.sha256:
                raise DifferError(f"trial: file bytes mismatch at {path!r}")
        elif want.type == "symlink":
            if got["linkname"] != want.linkname:
                raise DifferError(
                    f"trial: symlink text mismatch at {path!r}: "
                    f"want {want.linkname!r}, got {got['linkname']!r}"
                )

    # Hardlink grouping: compare the partition of regular-file paths by
    # inode token, singletons included, against the target tree.
    got_tokens = {}
    for path, st in state.items():
        if st["type"] == "file":
            got_tokens.setdefault(st["token"], set()).add(path)
    got_partition = {frozenset(s) for s in got_tokens.values()}
    want_groups = {frozenset(members) for members in new.groups.values()}
    linked = set().union(*want_groups) if want_groups else set()
    want_partition = set(want_groups) | {
        frozenset((p,))
        for p, node in new.nodes.items()
        if node.type == "file" and p not in linked
    }
    if got_partition != want_partition:
        raise DifferError(
            f"trial: hardlink grouping mismatch "
            f"(want {sorted(map(sorted, want_partition))[:5]}, "
            f"got {sorted(map(sorted, got_partition))[:5]})"
        )


# ---------------------------------------------------------------------------
# physical trial (real on-disk overlay, same code path as /unpack)
# ---------------------------------------------------------------------------


def physical_trial(old_layer_tars, diff_tar, new):
    """Really unpack the old image plus the diff layer; compare to target.

    This exercises the production overlay code path end to end. The
    privilege-independent :func:`simulate_layer` is authoritative for
    numeric UID/GID; here we check path set, entry types, permission bits,
    file bytes and symlink text, all of which are always observable.
    """
    import tempfile

    trial = tempfile.mkdtemp(prefix="trial-", dir=os.path.dirname(new.rootfs))
    try:
        dir_meta = {}
        for tar_path in old_layer_tars:
            apply_layer(tar_path, trial, dir_meta)
        apply_layer(diff_tar, trial, dir_meta)
        # Directory mode/mtime/owner is applied only after every layer has
        # been unpacked (same ordering as the production /unpack path).
        _apply_deferred_dir_meta(dir_meta)

        seen = set()
        for dirpath, dirnames, filenames in os.walk(trial, followlinks=False):
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, trial).replace(os.sep, "/")
                seen.add(rel)
                st = os.lstat(full)
                want = new.nodes.get(rel)
                if want is None:
                    raise DifferError(f"trial: unexpected path after overlay: {rel!r}")
                if stat.S_ISDIR(st.st_mode):
                    got_type = "dir"
                elif stat.S_ISLNK(st.st_mode):
                    got_type = "symlink"
                elif stat.S_ISREG(st.st_mode):
                    got_type = "file"
                else:
                    raise DifferError(
                        f"trial: unsupported file type after overlay at {rel!r}"
                    )
                if got_type != want.type:
                    raise DifferError(
                        f"trial: on-disk type mismatch at {rel!r}: "
                        f"want {want.type}, got {got_type}"
                    )
                # Permission bits are always settable and observable.
                if stat.S_IMODE(st.st_mode) != want.mode:
                    raise DifferError(
                        f"trial: on-disk mode mismatch at {rel!r}: "
                        f"want {oct(want.mode)}, got {oct(stat.S_IMODE(st.st_mode))}"
                    )
                if got_type == "file" and _hash_file(full) != want.sha256:
                    raise DifferError(f"trial: on-disk byte mismatch at {rel!r}")
                if got_type == "symlink" and os.readlink(full) != want.linkname:
                    raise DifferError(
                        f"trial: on-disk symlink text mismatch at {rel!r}"
                    )
        if seen != set(new.nodes):
            raise DifferError("trial: on-disk path set does not match target tree")
    finally:
        shutil.rmtree(trial, ignore_errors=True)


# ---------------------------------------------------------------------------
# top level
# ---------------------------------------------------------------------------


def _load_image(upload_path, workdir, name):
    """Verify an uploaded layout tar and unpack it into a rootfs tree."""
    layout_dir = os.path.join(workdir, f"{name}-layout")
    layer_dir = os.path.join(workdir, f"{name}-layers")
    rootfs = os.path.join(workdir, f"{name}-rootfs")
    os.makedirs(layout_dir)
    os.makedirs(layer_dir)
    os.makedirs(rootfs)
    extract_layout(upload_path, layout_dir)
    layer_tars, config = verify_layout(layout_dir, layer_dir)
    dir_meta = {}
    for tar_path in layer_tars:
        apply_layer(tar_path, rootfs, dir_meta)
    return rootfs, layer_tars, config


def _platform(config):
    if not isinstance(config, dict):
        raise DifferError("image config is not a JSON object")
    return (
        str(config.get("os", "")),
        str(config.get("architecture", "")),
        str(config.get("variant", "")),
    )


def make_diff_layer(old_upload, new_upload, workdir):
    """Build the verified diff layer tar; return its path.

    Raises :class:`UnpackError` or :class:`DifferError` on any problem.
    """
    old_rootfs, old_layer_tars, old_config = _load_image(
        old_upload, workdir, "old"
    )
    new_rootfs, new_layer_tars, new_config = _load_image(
        new_upload, workdir, "new"
    )

    if _platform(old_config) != _platform(new_config):
        raise DifferError(
            f"platform mismatch: old image is {_platform(old_config)}, "
            f"target image is {_platform(new_config)}"
        )

    # Logical trees come straight from the tar headers: authoritative
    # metadata and hardlink grouping regardless of host privileges.
    old = build_tree(old_layer_tars, old_rootfs)
    new = build_tree(new_layer_tars, new_rootfs)

    entries = compute_diff(old, new)
    diff_tar = os.path.join(workdir, "diff-layer.tar")
    build_layer_tar(entries, new_rootfs, diff_tar)

    # Verification 1: authoritative logical overlay (covers mode, numeric
    # UID/GID, second-resolution mtime, symlink text and hardlink groups
    # even when the process is unprivileged).
    simulate_layer(diff_tar, old, new)
    # Verification 2: real on-disk overlay through the production code path.
    physical_trial(old_layer_tars, diff_tar, new)
    return diff_tar
