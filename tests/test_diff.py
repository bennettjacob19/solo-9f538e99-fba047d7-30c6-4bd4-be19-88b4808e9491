"""End-to-end tests for the POST /diff differential layer service."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.sample_image import (
    MT_CONFIG,
    MT_INDEX,
    MT_LAYER,
    MT_LAYER_GZ,
    MT_MANIFEST,
)

FIXED_MTIME = 1_700_000_000


# ---------------------------------------------------------------------------
# OCI layout builder supporting metadata, hardlinks, symlinks and layers
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_layer_tar(entries):
    """entries: dicts with name/type and optional data,mode,uid,gid,mtime,target."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for e in entries:
            ti = tarfile.TarInfo(e["name"])
            ti.type = e["type"]
            ti.mode = e.get("mode", 0o755 if e["type"] == tarfile.DIRTYPE else 0o644)
            ti.mtime = e.get("mtime", FIXED_MTIME)
            ti.uid = e.get("uid", 0)
            ti.gid = e.get("gid", 0)
            data = b""
            if e["type"] == tarfile.REGTYPE:
                data = e.get("data", b"")
                if isinstance(data, str):
                    data = data.encode()
                ti.size = len(data)
            elif e["type"] in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                ti.linkname = e["target"]
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def build_image(layers, architecture="amd64", os_name="linux", variant=""):
    """Build a single-manifest OCI Image Layout tar from layer entry lists."""
    layer_blobs = []
    diff_ids = []
    for i, entries in enumerate(layers):
        raw = build_layer_tar(entries)
        if i % 2 == 1:  # exercise gzip layer support too
            blob = gzip.compress(raw, compresslevel=9, mtime=FIXED_MTIME)
            media = MT_LAYER_GZ
        else:
            blob = raw
            media = MT_LAYER
        layer_blobs.append((media, blob))
        diff_ids.append(f"sha256:{sha256(raw)}")

    config = {
        "architecture": architecture,
        "os": os_name,
        "created": "2026-01-01T00:00:00Z",
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
    }
    if variant:
        config["variant"] = variant
    config_b = json.dumps(config, sort_keys=True).encode()

    manifest = {
        "schemaVersion": 2,
        "mediaType": MT_MANIFEST,
        "config": {
            "mediaType": MT_CONFIG,
            "digest": f"sha256:{sha256(config_b)}",
            "size": len(config_b),
        },
        "layers": [
            {
                "mediaType": media,
                "digest": f"sha256:{sha256(blob)}",
                "size": len(blob),
            }
            for media, blob in layer_blobs
        ],
    }
    manifest_b = json.dumps(manifest, sort_keys=True).encode()

    index = {
        "schemaVersion": 2,
        "mediaType": MT_INDEX,
        "manifests": [
            {
                "mediaType": MT_MANIFEST,
                "digest": f"sha256:{sha256(manifest_b)}",
                "size": len(manifest_b),
                "annotations": {"org.opencontainers.image.ref.name": "img:latest"},
            }
        ],
    }
    index_b = json.dumps(index, sort_keys=True).encode()

    blobs = [config_b, manifest_b] + [blob for _, blob in layer_blobs]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in (
            ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
            ("index.json", index_b),
        ):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        for blob in blobs:
            name = f"blobs/sha256/{sha256(blob)}"
            ti = tarfile.TarInfo(name)
            ti.size = len(blob)
            tf.addfile(ti, io.BytesIO(blob))
    return buf.getvalue()


# entry shorthands -----------------------------------------------------------


def f(name, data, mode=0o644, uid=0, gid=0, mtime=FIXED_MTIME):
    return {
        "name": name,
        "type": tarfile.REGTYPE,
        "data": data,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "mtime": mtime,
    }


def d(name, mode=0o755, uid=0, gid=0, mtime=FIXED_MTIME):
    return {
        "name": name,
        "type": tarfile.DIRTYPE,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "mtime": mtime,
    }


def s(name, target, uid=0, gid=0, mtime=FIXED_MTIME):
    return {
        "name": name,
        "type": tarfile.SYMTYPE,
        "target": target,
        "mode": 0o777,
        "uid": uid,
        "gid": gid,
        "mtime": mtime,
    }


def h(name, target, mode=0o644, uid=0, gid=0, mtime=FIXED_MTIME):
    return {
        "name": name,
        "type": tarfile.LNKTYPE,
        "target": target,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "mtime": mtime,
    }


def wh(name):
    return {"name": name, "type": tarfile.REGTYPE, "data": b"", "mode": 0o000}


# ---------------------------------------------------------------------------
# response helpers
# ---------------------------------------------------------------------------


def _hardlink_targets(final):
    """Map LNKTYPE members to their link target in the output tar."""
    return {
        name: m.linkname
        for name, (m, _payload) in final.items()
        if m.islnk()
    }


def _same_inode(final, a, b):
    """Whether two output members share one inode (LNKTYPE relationship)."""
    links = _hardlink_targets(final)
    if a in links:
        return links[a] == b or links.get(b) == links[a]
    if b in links:
        return links[b] == a or links.get(a) == links[b]
    return False


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def post_diff(client, old_bytes, new_bytes):
    return client.post(
        "/diff",
        files={
            "old_image": ("old.tar", old_bytes, "application/x-tar"),
            "new_image": ("new.tar", new_bytes, "application/x-tar"),
        },
    )


def read_diff_tar(content):
    members = {}
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as tf:
        for m in tf.getmembers():
            payload = None
            if m.isreg():
                payload = tf.extractfile(m).read()
            members[m.name] = (m, payload)
    return members


def apply_diff_to_old(client, old_bytes, diff_bytes):
    """Rebuild a full image = old layers + diff layer and unpack it via /unpack."""
    # Extract the old layout's blobs and JSON.
    old_files = {}
    with tarfile.open(fileobj=io.BytesIO(old_bytes), mode="r:") as tf:
        for m in tf.getmembers():
            if m.isreg():
                old_files[m.name] = tf.extractfile(m).read()
    manifest_hex = json.loads(old_files["index.json"])["manifests"][0]["digest"].split(
        ":"
    )[1]
    manifest = json.loads(old_files[f"blobs/sha256/{manifest_hex}"])
    config_hex = manifest["config"]["digest"].split(":")[1]
    config = json.loads(old_files[f"blobs/sha256/{config_hex}"])

    diff_hex = sha256(diff_bytes)
    config["rootfs"]["diff_ids"].append(f"sha256:{diff_hex}")
    config_b = json.dumps(config, sort_keys=True).encode()
    new_config_hex = sha256(config_b)
    manifest["config"] = {
        "mediaType": MT_CONFIG,
        "digest": f"sha256:{new_config_hex}",
        "size": len(config_b),
    }
    manifest["layers"].append(
        {
            "mediaType": MT_LAYER,
            "digest": f"sha256:{diff_hex}",
            "size": len(diff_bytes),
        }
    )
    manifest_b = json.dumps(manifest, sort_keys=True).encode()
    new_manifest_hex = sha256(manifest_b)
    index = {
        "schemaVersion": 2,
        "mediaType": MT_INDEX,
        "manifests": [
            {
                "mediaType": MT_MANIFEST,
                "digest": f"sha256:{new_manifest_hex}",
                "size": len(manifest_b),
            }
        ],
    }
    index_b = json.dumps(index, sort_keys=True).encode()

    files = dict(old_files)
    files["index.json"] = index_b
    files[f"blobs/sha256/{new_config_hex}"] = config_b
    files[f"blobs/sha256/{new_manifest_hex}"] = manifest_b
    files[f"blobs/sha256/{diff_hex}"] = diff_bytes

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in sorted(files.items()):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

    r = client.post(
        "/unpack",
        files={"file": ("merged.tar", buf.getvalue(), "application/x-tar")},
    )
    assert r.status_code == 200, r.text
    result = {}
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:") as tf:
        for m in tf.getmembers():
            payload = None
            if m.isreg():
                payload = tf.extractfile(m).read()
            result[m.name] = (m, payload)
    return result


# ---------------------------------------------------------------------------
# happy path: basic change set
# ---------------------------------------------------------------------------


BASE = [
    d("etc"),
    f("etc/keep.conf", "keep\n"),
    f("etc/mod.conf", "v1\n", mode=0o644),
    d("app"),
    f("app/a.txt", "aaa\n"),
    f("app/gone.txt", "bye\n"),
    f("app/content.bin", b"x" * 100),
]


def target_basic():
    return [
        d("etc"),
        f("etc/keep.conf", "keep\n"),
        f("etc/mod.conf", "v2\n", mode=0o600, uid=1000, gid=1000),
        d("app"),
        f("app/a.txt", "aaa-changed\n"),
        f("app/content.bin", b"x" * 100),  # identical bytes -> reused
        f("app/new.txt", "fresh\n"),
        d("app/newdir"),
        f("app/newdir/n.txt", "nested\n"),
    ]


def test_basic_diff_roundtrip(client):
    old = build_image([BASE])
    new = build_image([target_basic()])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/x-tar"
    members = read_diff_tar(r.content)

    # deletion represented by whiteout
    assert "app/.wh.gone.txt" in members
    # unchanged files are not carried in the layer
    assert "etc/keep.conf" not in members
    assert "app/content.bin" not in members
    # changed / new entries are
    assert "app/a.txt" in members
    assert "app/new.txt" in members
    assert "app/newdir" in members
    assert "app/newdir/n.txt" in members
    # metadata change is reflected on the emitted member
    m, _ = members["etc/mod.conf"]
    assert m.mode == 0o600 and m.uid == 1000 and m.gid == 1000
    assert m.mtime == FIXED_MTIME

    # Append the layer to the old image for real and unpack via /unpack.
    final = apply_diff_to_old(client, old, r.content)
    assert "app/gone.txt" not in final
    assert final["etc/keep.conf"][1] == b"keep\n"
    assert final["etc/mod.conf"][1] == b"v2\n"
    assert final["app/a.txt"][1] == b"aaa-changed\n"
    assert final["app/new.txt"][1] == b"fresh\n"
    assert final["app/newdir/n.txt"][1] == b"nested\n"
    assert final["app/content.bin"][1] == b"x" * 100
    m, _ = final["etc/mod.conf"]
    assert m.mode == 0o600
    if os.geteuid() == 0:
        assert m.uid == 1000 and m.gid == 1000


def test_identical_images_produce_empty_layer(client):
    img = build_image([BASE])
    r = post_diff(client, img, img)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    assert members == {}
    # and appending it still reproduces the tree
    final = apply_diff_to_old(client, img, r.content)
    assert final["etc/keep.conf"][1] == b"keep\n"


def test_response_is_uncompressed_tar(client):
    old = build_image([BASE])
    new = build_image([target_basic()])
    r = post_diff(client, old, new)
    assert r.status_code == 200
    # gzip magic must not appear; tar ustar/PAX magic appears at offset 257
    assert not r.content.startswith(b"\x1f\x8b")
    assert r.content[257:262] == b"ustar"


# ---------------------------------------------------------------------------
# type swaps
# ---------------------------------------------------------------------------


def test_directory_becomes_file(client):
    old = build_image([[d("x"), f("x/child", "c\n")]])
    new = build_image([[f("x", "now a file\n", mode=0o755)]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    assert "x/.wh.child" in members or ".wh.x" in members
    assert "x" in members and members["x"][0].isreg()
    final = apply_diff_to_old(client, old, r.content)
    assert final["x"][1] == b"now a file\n"
    assert "x/child" not in final


def test_file_becomes_directory(client):
    old = build_image([[f("x", "was a file\n")]])
    new = build_image([[d("x"), f("x/child", "c\n")]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    assert ".wh.x" in members
    assert members["x"][0].isdir()
    assert members["x/child"][1] == b"c\n"
    final = apply_diff_to_old(client, old, r.content)
    assert "x" in final and final["x"][0].isdir()
    assert final["x/child"][1] == b"c\n"


def test_file_becomes_symlink_and_back(client):
    old = build_image([[f("linkme", "data\n"), s("ln", "linkme")]])
    new = build_image(
        [[f("linkme", "data\n"), f("ln", "now regular\n", mode=0o755)]]
    )
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    assert ".wh.ln" in members and members["ln"][0].isreg()
    final = apply_diff_to_old(client, old, r.content)
    assert final["ln"][1] == b"now regular\n"

    # reverse direction: regular file -> symlink
    r2 = post_diff(client, new, old)
    assert r2.status_code == 200, r2.text
    members2 = read_diff_tar(r2.content)
    assert members2["ln"][0].issym() and members2["ln"][0].linkname == "linkme"
    final2 = apply_diff_to_old(client, new, r2.content)
    m, _ = final2["ln"]
    assert m.issym() and m.linkname == "linkme"


# ---------------------------------------------------------------------------
# hardlinks: split, merge, regroup with identical bytes
# ---------------------------------------------------------------------------


def test_hardlink_split_identical_bytes(client):
    # a and b share one inode in the old image; target keeps identical bytes
    # but they must become independent files.
    old = build_image([[f("a", "same\n"), h("b", "a")]])
    new = build_image([[f("a", "same\n"), f("b", "same\n")]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    # a full regular entry must appear (the group is broken), content reused
    # only when possible; at minimum one of them is emitted.
    assert any(m.isreg() for m, _ in members.values())
    final = apply_diff_to_old(client, old, r.content)
    ma, mb = final["a"][0], final["b"][0]
    assert ma.isreg() and mb.isreg()
    # independent inodes in the merged image output
    assert not _same_inode(final, "a", "b")
    assert final["a"][1] == final["b"][1] == b"same\n"


def test_hardlink_merge_identical_bytes(client):
    old = build_image([[f("a", "same\n"), f("b", "same\n")]])
    new = build_image([[f("a", "same\n"), h("b", "a")]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    # The hardlink entry is the essential payload; the lower-layer anchor
    # 'a' (identical bytes+meta) is reused, so no file content is shipped.
    assert "b" in members and members["b"][0].islnk()
    assert members["b"][0].linkname == "a"
    assert not any(
        m.isreg() and payload for m, payload in members.values()
    )
    final = apply_diff_to_old(client, old, r.content)
    # the output tar may express the shared inode as LNKTYPE or as two
    # regular members with one inode number; either way they share an inode
    assert _same_inode(final, "a", "b")


def test_hardlink_regroup_three_way(client):
    # old: (a,b) group ; new: (b,c) group, all bytes identical
    old = build_image([[f("a", "z\n"), h("b", "a"), f("c", "z\n")]])
    new = build_image([[f("a", "z\n"), f("b", "z\n"), h("c", "b")]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    final = apply_diff_to_old(client, old, r.content)
    # b and c share an inode; a does not share with either
    assert _same_inode(final, "b", "c")
    assert not _same_inode(final, "a", "b")
    assert not _same_inode(final, "a", "c")


def test_unchanged_hardlink_group_omitted(client):
    old = build_image([[d("g"), f("g/a", "shared\n"), h("g/b", "g/a")]])
    new = build_image(
        [[d("g"), f("g/a", "shared\n"), h("g/b", "g/a"), f("g/c", "new\n")]]
    )
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    assert "g/a" not in members and "g/b" not in members
    assert members["g/c"][1] == b"new\n"
    final = apply_diff_to_old(client, old, r.content)
    m, _ = final["g/b"]
    assert m.islnk() and m.linkname == "g/a"


# ---------------------------------------------------------------------------
# metadata and mtime semantics
# ---------------------------------------------------------------------------


def test_only_metadata_changes(client):
    old = build_image([[f("meta", "payload\n", mode=0o644, uid=0, gid=0)]])
    new = build_image(
        [[f("meta", "payload\n", mode=0o755, uid=42, gid=43, mtime=1_700_999_999)]]
    )
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    m, payload = members["meta"]
    assert m.mode == 0o755 and m.mtime == 1_700_999_999 and payload == b"payload\n"
    # The layer always carries the target numeric owner; whether the later
    # /unpack can apply chown depends on process privileges.
    assert m.uid == 42 and m.gid == 43
    final = apply_diff_to_old(client, old, r.content)
    m, _ = final["meta"]
    assert m.mode == 0o755 and m.mtime == 1_700_999_999
    if os.geteuid() == 0:
        assert m.uid == 42 and m.gid == 43


def test_directory_metadata_and_mtime_replayed(client):
    old = build_image(
        [[d("dir", mode=0o755, mtime=1_700_000_000), f("dir/f", "1\n")]]
    )
    new = build_image(
        [
            [
                d("dir", mode=0o700, uid=7, gid=8, mtime=1_700_555_555),
                f("dir/f", "2\n"),
            ]
        ]
    )
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    dm = members["dir"][0]
    assert dm.mode == 0o700 and dm.uid == 7 and dm.gid == 8
    assert dm.mtime == 1_700_555_555
    final = apply_diff_to_old(client, old, r.content)
    m, _ = final["dir"]
    assert m.mode == 0o700 and m.mtime == 1_700_555_555
    if os.geteuid() == 0:
        assert m.uid == 7 and m.gid == 8


def test_symlink_text_change(client):
    old = build_image([[f("target1", "1\n"), f("target2", "2\n"), s("ln", "target1")]])
    new = build_image([[f("target1", "1\n"), f("target2", "2\n"), s("ln", "target2")]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    assert members["ln"][0].linkname == "target2"
    final = apply_diff_to_old(client, old, r.content)
    m, _ = final["ln"]
    assert m.issym() and m.linkname == "target2"


# ---------------------------------------------------------------------------
# platform / input validation
# ---------------------------------------------------------------------------


def test_platform_mismatch_rejected(client):
    old = build_image([BASE], architecture="amd64")
    new = build_image([target_basic()], architecture="arm64")
    r = post_diff(client, old, new)
    assert r.status_code == 400
    assert "platform" in r.json()["detail"]


def test_variant_mismatch_rejected(client):
    old = build_image([BASE], architecture="arm64", variant="v7")
    new = build_image([target_basic()], architecture="arm64", variant="v8")
    r = post_diff(client, old, new)
    assert r.status_code == 400
    assert "platform" in r.json()["detail"]


def test_corrupt_old_image_rejected(client):
    new = build_image([target_basic()])
    r = post_diff(client, b"not a tar at all", new)
    assert r.status_code == 400


def test_corrupt_new_image_rejected(client):
    old = build_image([BASE])
    r = post_diff(client, old, b"also not a tar")
    assert r.status_code == 400


def test_unsupported_fifo_rejected(client, tmp_path):
    # Build a valid image whose unpacked tree contains a FIFO via a crafted
    # layer tar (the /unpack verifier accepts fifos; /diff must reject).
    fifo_layer = build_layer_tar(
        [{"name": "pipe", "type": tarfile.FIFOTYPE, "mode": 0o644}]
    )
    new = build_image([target_basic()])
    # Inject the fifo layer into a copy of the new image.
    files = {}
    with tarfile.open(fileobj=io.BytesIO(new), mode="r:") as tf:
        for m in tf.getmembers():
            if m.isreg():
                files[m.name] = tf.extractfile(m).read()
    mh = json.loads(files["index.json"])["manifests"][0]["digest"].split(":")[1]
    manifest = json.loads(files[f"blobs/sha256/{mh}"])
    ch = manifest["config"]["digest"].split(":")[1]
    config = json.loads(files[f"blobs/sha256/{ch}"])
    layer_hex = sha256(fifo_layer)
    files[f"blobs/sha256/{layer_hex}"] = fifo_layer
    manifest["layers"].append(
        {"mediaType": MT_LAYER, "digest": f"sha256:{layer_hex}",
         "size": len(fifo_layer)}
    )
    config["rootfs"]["diff_ids"].append(f"sha256:{layer_hex}")
    config_b = json.dumps(config, sort_keys=True).encode()
    new_ch = sha256(config_b)
    files[f"blobs/sha256/{new_ch}"] = config_b
    manifest["config"] = {
        "mediaType": MT_CONFIG, "digest": f"sha256:{new_ch}", "size": len(config_b)
    }
    manifest_b = json.dumps(manifest, sort_keys=True).encode()
    new_mh = sha256(manifest_b)
    files[f"blobs/sha256/{new_mh}"] = manifest_b
    files["index.json"] = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": MT_INDEX,
            "manifests": [
                {"mediaType": MT_MANIFEST, "digest": f"sha256:{new_mh}",
                 "size": len(manifest_b)}
            ],
        },
        sort_keys=True,
    ).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in sorted(files.items()):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    old = build_image([target_basic()])
    r = post_diff(client, old, buf.getvalue())
    assert r.status_code == 400
    assert "unsupported file type" in r.json()["detail"]


# ---------------------------------------------------------------------------
# multi-layer images and whiteout input
# ---------------------------------------------------------------------------


def test_multi_layer_old_image_with_whiteouts(client):
    old = build_image(
        [
            [d("app"), f("app/base.txt", "base\n"), f("app/drop.txt", "x\n")],
            [wh("app/.wh.drop.txt"), f("app/top.txt", "top\n")],
        ]
    )
    new = build_image(
        [
            [d("app"), f("app/base.txt", "base\n")],
            [f("app/top.txt", "top v2\n"), d("app/sub"), f("app/sub/n.txt", "n\n")],
        ]
    )
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    assert "app/.wh.drop.txt" not in members  # already absent in old tree
    final = apply_diff_to_old(client, old, r.content)
    assert "app/drop.txt" not in final
    assert final["app/base.txt"][1] == b"base\n"
    assert final["app/top.txt"][1] == b"top v2\n"
    assert final["app/sub/n.txt"][1] == b"n\n"


def test_diff_against_sample_image(client):
    r = client.get("/sample-image")
    assert r.status_code == 200
    sample = r.content
    # target = same content plus one new file; diff must apply cleanly
    target = build_image(
        [
            [
                d("etc"),
                f("etc/motd", "hello from sample image\n"),
                d("bin"),
                f("bin/tool", "tool-v1\n", mode=0o755),
                h("bin/tool-link", "bin/tool"),
                d("app"),
                f("app/config.txt", "config v1\n"),
                d("app/data"),
                f("app/data/keep.txt", "keep me\n"),
                f("app/data/remove.txt", "remove me\n"),
                f("app/data/rebuilt.txt", "rebuilt: old\n"),
                d("secret", mode=0o700),
                f("secret/token.txt", "secret-token\n", mode=0o600),
            ],
            [
                wh("app/data/.wh.remove.txt"),
                wh("app/.wh.config.txt"),
                wh("secret/.wh..wh..opq"),
                f("secret/public.txt", "now public\n"),
                f("bin/tool", "tool-v2\n", mode=0o755),
                s("bin/tool-alias", "tool"),
                s("etc/motd-link", "/etc/motd"),
                f("app/data/rebuilt.txt", "rebuilt: new\n"),
                wh("app/data/.wh.rebuilt.txt"),
                f("app/data/added.txt", "added by diff\n"),
            ],
        ]
    )
    r = post_diff(client, sample, target)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    assert members["app/data/added.txt"][1] == b"added by diff\n"
    final = apply_diff_to_old(client, sample, r.content)
    assert final["app/data/added.txt"][1] == b"added by diff\n"
    assert final["bin/tool"][1] == b"tool-v2\n"
    assert final["bin/tool-link"][1] == b"tool-v1\n"
    assert "secret/token.txt" not in final


# ---------------------------------------------------------------------------
# blockwise processing
# ---------------------------------------------------------------------------


def test_large_file_processed_in_blocks(client):
    # 6 MiB file: far larger than the 1 MiB processing chunk
    payload = os.urandom(6 * 1024 * 1024)
    old = build_image([[f("big.bin", b"small\n")]])
    new = build_image([[f("big.bin", payload)]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    final = apply_diff_to_old(client, old, r.content)
    assert final["big.bin"][1] == payload


# ---------------------------------------------------------------------------
# whiteout minimality and empty layer shape
# ---------------------------------------------------------------------------


def test_whiteout_naming_and_minimality(client):
    old = build_image(
        [[d("tree"), f("tree/one", "1\n"), f("tree/two", "2\n"), f("solo", "x\n")]]
    )
    new = build_image(
        [[f("tree", "now a file\n"), f("solo", "x\n")]]
    )
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    # one whiteout on the directory removes the whole subtree; no redundant
    # child whiteouts are emitted
    assert ".wh.tree" in members
    assert "tree/.wh.one" not in members
    assert "tree/.wh.two" not in members
    assert members["tree"][0].isreg()
    # unrelated paths stay in lower layers and are untouched
    assert "solo" not in members
    final = apply_diff_to_old(client, old, r.content)
    assert final["tree"][1] == b"now a file\n"
    assert "tree/one" not in final and "tree/two" not in final
    assert final["solo"][1] == b"x\n"


def test_empty_file_reuse_and_root_swap(client):
    old = build_image([[f("empty", b""), d("top"), f("top/x", "1\n")]])
    new = build_image([[f("empty", b""), f("top", "file now\n")]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    # unchanged zero-size file is reused from the lower layer
    assert "empty" not in members
    assert ".wh.top" in members
    final = apply_diff_to_old(client, old, r.content)
    assert final["empty"][1] == b""
    assert final["top"][1] == b"file now\n"
    assert "top/x" not in final

    # empty -> non-empty transition is emitted as a regular entry
    r2 = post_diff(
        client,
        build_image([[f("grew", b"")]]),
        build_image([[f("grew", b"now has content\n")]]),
    )
    assert r2.status_code == 200, r2.text
    final2 = apply_diff_to_old(client, build_image([[f("grew", b"")]]), r2.content)
    assert final2["grew"][1] == b"now has content\n"


def test_identical_multi_layer_image_empty_tar(client):
    img = build_image(
        [[d("a"), f("a/x", "1\n")], [f("a/y", "2\n"), wh("a/.wh.z")]]
    )
    r = post_diff(client, img, img)
    assert r.status_code == 200, r.text
    members = read_diff_tar(r.content)
    assert members == {}
    final = apply_diff_to_old(client, img, r.content)
    assert final["a/x"][1] == b"1\n" and final["a/y"][1] == b"2\n"


def test_deleted_symlink_uses_whiteout(client):
    old = build_image([[f("t", "x\n"), s("ln", "t")]])
    new = build_image([[f("t", "x\n")]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    assert ".wh.ln" in read_diff_tar(r.content)
    final = apply_diff_to_old(client, old, r.content)
    assert "ln" not in final


def test_diff_layer_entries_are_sorted_and_anchored(client):
    # Every LNKTYPE member must reference an anchor; when an anchor is
    # emitted as a regular entry it has to precede its hardlink members.
    old = build_image([[f("a", "old\n"), f("b", "z\n"), f("c", "z\n")]])
    new = build_image([[f("a", "z\n"), h("b", "a"), h("c", "a")]])
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:") as tf:
        members = tf.getmembers()
        names = [m.name for m in members]
        regular = {m.name for m in members if m.isreg()}
        for m in members:
            if m.islnk():
                # target is either an anchor emitted in this layer (earlier
                # in the tar) or an entry inherited from lower layers
                if m.linkname in regular:
                    assert names.index(m.linkname) < names.index(m.name)
    final = apply_diff_to_old(client, old, r.content)
    assert _same_inode(final, "a", "b") and _same_inode(final, "a", "c")


def test_cross_layer_hardlink_split_and_merge_with_gzip(client):
    # Layer 2 (gzip) creates a hardlink to a layer-1 regular file.
    old = build_image(
        [
            [d("data"), f("data/base.bin", "layer1 bytes\n")],
            [h("data/link.bin", "data/base.bin")],
        ]
    )
    new = build_image(
        [
            [d("data"), f("data/base.bin", "layer1 bytes\n")],
            [f("data/link.bin", "now independent but same bytes\n")],
            [f("data/extra.txt", "added\n")],
        ]
    )
    r = post_diff(client, old, new)
    assert r.status_code == 200, r.text
    final = apply_diff_to_old(client, old, r.content)
    assert not _same_inode(final, "data/base.bin", "data/link.bin")
    assert final["data/link.bin"][1] == b"now independent but same bytes\n"
    assert final["data/base.bin"][1] == b"layer1 bytes\n"
    assert final["data/extra.txt"][1] == b"added\n"

    # Reverse: independent files merge into a cross-layer hardlink group.
    r2 = post_diff(client, new, old)
    assert r2.status_code == 200, r2.text
    final2 = apply_diff_to_old(client, new, r2.content)
    assert _same_inode(final2, "data/base.bin", "data/link.bin")

    # The second layer really is gzip-compressed in the layout.
    files = {}
    with tarfile.open(fileobj=io.BytesIO(old), mode="r:") as tf:
        for m in tf.getmembers():
            if m.isreg():
                files[m.name] = tf.extractfile(m).read()
    mh = json.loads(files["index.json"])["manifests"][0]["digest"].split(":")[1]
    manifest = json.loads(files[f"blobs/sha256/{mh}"])
    assert manifest["layers"][1]["mediaType"] == MT_LAYER_GZ
