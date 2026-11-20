"""Build the sample OCI Image Layout tar served at GET /sample-image.

The sample image has two layers (layer 1 gzip-compressed, layer 2 a plain
tar) and exercises every tricky behaviour of the unpacker:

* plain deletions via ``.wh.<name>`` whiteouts;
* an opaque directory (``.wh..wh..opq``) that hides lower-layer content
  while same-layer additions survive;
* a whiteout that appears *after* the same-layer file it names -- the new
  file must survive because whiteouts only delete lower-layer content;
* one end of a hardlink pair being overwritten -- the other end must keep
  its original bytes;
* relative and absolute symlinks;
* permission bits (0755 executables, 0600 secrets, 0700 directory).

Expected final rootfs::

    app/data/keep.txt       "keep me\n"
    app/data/rebuilt.txt    "rebuilt: new\n"      (same-layer whiteout must not delete it)
    bin/tool                "tool-v2\n"  mode 0755 (overwritten end of the hardlink pair)
    bin/tool-link           "tool-v1\n"            (other end keeps original bytes)
    bin/tool-alias          symlink -> "tool"
    etc/motd                "hello from sample image\n"
    etc/motd-link           symlink -> "/etc/motd"
    secret/public.txt       "now public\n"         (opaque dir: token.txt is gone)

Removed from the lower layer: ``app/config.txt``, ``app/data/remove.txt``,
``secret/token.txt``.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile

MT_INDEX = "application/vnd.oci.image.index.v1+json"
MT_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MT_CONFIG = "application/vnd.oci.image.config.v1+json"
MT_LAYER = "application/vnd.oci.image.layer.v1.tar"
MT_LAYER_GZ = "application/vnd.oci.image.layer.v1.tar+gzip"

FIXED_MTIME = 1_700_000_000  # deterministic output


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ti(name, type_, mode, size=0, linkname=""):
    ti = tarfile.TarInfo(name)
    ti.type = type_
    ti.mode = mode
    ti.mtime = FIXED_MTIME
    ti.uid = 0
    ti.gid = 0
    ti.uname = "root"
    ti.gname = "root"
    ti.size = size
    ti.linkname = linkname
    return ti


def _add_file(tf, name, data: bytes, mode=0o644):
    tf.addfile(_ti(name, tarfile.REGTYPE, mode, size=len(data)), io.BytesIO(data))


def _add_dir(tf, name, mode=0o755):
    tf.addfile(_ti(name, tarfile.DIRTYPE, mode))


def _add_symlink(tf, name, target):
    tf.addfile(_ti(name, tarfile.SYMTYPE, 0o777, linkname=target))


def _add_hardlink(tf, name, target):
    tf.addfile(_ti(name, tarfile.LNKTYPE, 0o644, linkname=target))


def _add_whiteout(tf, name):
    _add_file(tf, name, b"", 0o000)


def _layer1_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        _add_dir(tf, "etc")
        _add_file(tf, "etc/motd", b"hello from sample image\n")
        _add_dir(tf, "bin")
        _add_file(tf, "bin/tool", b"tool-v1\n", 0o755)
        _add_hardlink(tf, "bin/tool-link", "bin/tool")
        _add_dir(tf, "app")
        _add_file(tf, "app/config.txt", b"config v1\n")
        _add_dir(tf, "app/data")
        _add_file(tf, "app/data/keep.txt", b"keep me\n")
        _add_file(tf, "app/data/remove.txt", b"remove me\n")
        _add_file(tf, "app/data/rebuilt.txt", b"rebuilt: old\n")
        _add_dir(tf, "secret", 0o700)
        _add_file(tf, "secret/token.txt", b"secret-token\n", 0o600)
    return buf.getvalue()


def _layer2_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        # plain whiteouts: delete lower-layer files
        _add_whiteout(tf, "app/data/.wh.remove.txt")
        _add_whiteout(tf, "app/.wh.config.txt")
        # opaque directory: hide everything the lower layers put into secret/
        _add_whiteout(tf, "secret/.wh..wh..opq")
        _add_file(tf, "secret/public.txt", b"now public\n")
        # overwrite ONE end of the bin/tool <-> bin/tool-link hardlink pair
        _add_file(tf, "bin/tool", b"tool-v2\n", 0o755)
        _add_symlink(tf, "bin/tool-alias", "tool")
        _add_symlink(tf, "etc/motd-link", "/etc/motd")
        # same-layer new file followed by its own whiteout: the whiteout only
        # affects lower layers, so the new content must survive
        _add_file(tf, "app/data/rebuilt.txt", b"rebuilt: new\n")
        _add_whiteout(tf, "app/data/.wh.rebuilt.txt")
    return buf.getvalue()


def build_sample_image(dest_path: str) -> None:
    layer1 = _layer1_tar()
    layer2 = _layer2_tar()
    layer1_gz = gzip.compress(layer1, compresslevel=9, mtime=FIXED_MTIME)

    config = {
        "architecture": "amd64",
        "os": "linux",
        "created": "2026-01-01T00:00:00Z",
        "rootfs": {
            "type": "layers",
            "diff_ids": [f"sha256:{_sha256(layer1)}", f"sha256:{_sha256(layer2)}"],
        },
        "history": [
            {"created": "2026-01-01T00:00:00Z", "comment": "base layer (gzip)"},
            {"created": "2026-01-01T00:00:01Z",
             "comment": "whiteouts + opaque dir + hardlink overwrite (plain tar)"},
        ],
    }
    config_b = json.dumps(config, sort_keys=True).encode()

    manifest = {
        "schemaVersion": 2,
        "mediaType": MT_MANIFEST,
        "config": {
            "mediaType": MT_CONFIG,
            "digest": f"sha256:{_sha256(config_b)}",
            "size": len(config_b),
        },
        "layers": [
            {"mediaType": MT_LAYER_GZ,
             "digest": f"sha256:{_sha256(layer1_gz)}", "size": len(layer1_gz)},
            {"mediaType": MT_LAYER,
             "digest": f"sha256:{_sha256(layer2)}", "size": len(layer2)},
        ],
    }
    manifest_b = json.dumps(manifest, sort_keys=True).encode()

    index = {
        "schemaVersion": 2,
        "mediaType": MT_INDEX,
        "manifests": [{
            "mediaType": MT_MANIFEST,
            "digest": f"sha256:{_sha256(manifest_b)}",
            "size": len(manifest_b),
            "annotations": {"org.opencontainers.image.ref.name": "sample:latest"},
        }],
    }
    index_b = json.dumps(index, sort_keys=True).encode()

    blobs = {
        f"blobs/sha256/{_sha256(config_b)}": config_b,
        f"blobs/sha256/{_sha256(manifest_b)}": manifest_b,
        f"blobs/sha256/{_sha256(layer1_gz)}": layer1_gz,
        f"blobs/sha256/{_sha256(layer2)}": layer2,
    }

    tmp = dest_path + ".tmp"
    with tarfile.open(tmp, "w", format=tarfile.PAX_FORMAT) as tf:
        _add_file(tf, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        _add_file(tf, "index.json", index_b)
        _add_dir(tf, "blobs")
        _add_dir(tf, "blobs/sha256")
        for name in sorted(blobs):
            _add_file(tf, name, blobs[name])
    os.replace(tmp, dest_path)
