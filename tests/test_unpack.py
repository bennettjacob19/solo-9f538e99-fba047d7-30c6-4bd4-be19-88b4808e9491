"""End-to-end tests for the OCI image unpacker service."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.sample_image import MT_CONFIG, MT_LAYER, MT_LAYER_GZ, MT_MANIFEST


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unpack(client, data: bytes):
    return client.post(
        "/unpack", files={"file": ("image.tar", data, "application/x-tar")}
    )


def read_rootfs(content: bytes):
    """Turn a rootfs.tar into {name: (kind, payload)}."""
    result = {}
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as tf:
        for m in tf.getmembers():
            if m.isdir():
                result[m.name] = ("dir", None)
            elif m.issym():
                result[m.name] = ("symlink", m.linkname)
            elif m.islnk():
                result[m.name] = ("hardlink", m.linkname)
            elif m.isreg():
                result[m.name] = ("file", tf.extractfile(m).read())
    return result


def read_layout(data: bytes):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf.getmembers():
            if m.isreg():
                files[m.name] = tf.extractfile(m).read()
    return files


def write_layout(files) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name in sorted(files):
            ti = tarfile.TarInfo(name)
            ti.size = len(files[name])
            tf.addfile(ti, io.BytesIO(files[name]))
    return buf.getvalue()


class LayoutEditor:
    """Read/modify/write an OCI layout tar, fixing up descriptors."""

    def __init__(self, data: bytes):
        self.files = read_layout(data)

    def _manifest_desc(self):
        return json.loads(self.files["index.json"])["manifests"][0]

    def manifest(self):
        d = self._manifest_desc()["digest"].split(":")[1]
        return json.loads(self.files[f"blobs/sha256/{d}"])

    def _write_manifest(self, manifest):
        raw = json.dumps(manifest).encode()
        h = sha256(raw)
        self.files[f"blobs/sha256/{h}"] = raw
        idx = json.loads(self.files["index.json"])
        idx["manifests"][0] = {
            "mediaType": MT_MANIFEST,
            "digest": f"sha256:{h}",
            "size": len(raw),
        }
        self.files["index.json"] = json.dumps(idx).encode()

    def config(self):
        d = self.manifest()["config"]["digest"].split(":")[1]
        return json.loads(self.files[f"blobs/sha256/{d}"])

    def set_config(self, config):
        raw = json.dumps(config).encode()
        h = sha256(raw)
        self.files[f"blobs/sha256/{h}"] = raw
        m = self.manifest()
        m["config"] = {
            "mediaType": MT_CONFIG,
            "digest": f"sha256:{h}",
            "size": len(raw),
        }
        self._write_manifest(m)

    def set_layer_blob(self, i, media_type, raw: bytes):
        h = sha256(raw)
        self.files[f"blobs/sha256/{h}"] = raw
        m = self.manifest()
        m["layers"][i] = {
            "mediaType": media_type,
            "digest": f"sha256:{h}",
            "size": len(raw),
        }
        self._write_manifest(m)

    def set_layer_blob_no_desc_fix(self, digest_hex, raw: bytes):
        """Overwrite a blob in place: descriptor now mismatches."""
        self.files[f"blobs/sha256/{digest_hex}"] = raw

    def layer_digest(self, i):
        return self.manifest()["layers"][i]["digest"].split(":")[1]

    def to_bytes(self) -> bytes:
        return write_layout(self.files)


def make_layer(entries) -> bytes:
    """entries: list of (name, kind, payload); kind in
    file/dir/symlink/hardlink."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, kind, payload in entries:
            ti = tarfile.TarInfo(name)
            ti.mtime = 1_700_000_000
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "file":
                data = payload if isinstance(payload, bytes) else payload.encode()
                ti.type = tarfile.REGTYPE
                ti.mode = 0o644
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            elif kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tf.addfile(ti)
            elif kind == "hardlink":
                ti.type = tarfile.LNKTYPE
                ti.linkname = payload
                tf.addfile(ti)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def sample(client):
    r = client.get("/sample-image")
    assert r.status_code == 200
    return r.content


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------


def test_docs_available(client):
    assert client.get("/docs").status_code == 200
    assert client.get("/healthz").status_code == 200


def test_sample_roundtrip(client, sample):
    r = unpack(client, sample)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/x-tar"
    fs = read_rootfs(r.content)

    # plain files survive
    assert fs["app/data/keep.txt"] == ("file", b"keep me\n")
    assert fs["etc/motd"] == ("file", b"hello from sample image\n")

    # whiteout deletions of lower-layer files
    assert "app/config.txt" not in fs
    assert "app/data/remove.txt" not in fs

    # opaque dir: lower content gone, same-layer addition survives
    assert "secret/token.txt" not in fs
    assert fs["secret/public.txt"] == ("file", b"now public\n")

    # same-layer file + whiteout (marker AFTER the file): new file survives
    assert fs["app/data/rebuilt.txt"] == ("file", b"rebuilt: new\n")

    # hardlink overwrite: bin/tool replaced, bin/tool-link keeps old bytes
    assert fs["bin/tool"] == ("file", b"tool-v2\n")
    assert fs["bin/tool-link"] == ("file", b"tool-v1\n")

    # symlinks
    assert fs["bin/tool-alias"] == ("symlink", "tool")
    assert fs["etc/motd-link"] == ("symlink", "/etc/motd")

    # permissions
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:") as tf:
        assert tf.getmember("bin/tool").mode == 0o755
        assert tf.getmember("secret").mode == 0o700


def test_failed_request_does_not_affect_others(client, sample):
    bad = LayoutEditor(sample)
    bad.set_layer_blob(0, MT_LAYER_GZ, b"definitely not gzip")
    r = unpack(client, bad.to_bytes())
    assert r.status_code == 400
    # a good request right after still works
    r = unpack(client, sample)
    assert r.status_code == 200
    fs = read_rootfs(r.content)
    assert fs["bin/tool"] == ("file", b"tool-v2\n")


# ---------------------------------------------------------------------------
# verification failures
# ---------------------------------------------------------------------------


def test_missing_blob(client, sample):
    ed = LayoutEditor(sample)
    del ed.files[f"blobs/sha256/{ed.layer_digest(1)}"]
    r = unpack(client, ed.to_bytes())
    assert r.status_code == 400
    assert "missing blob" in r.json()["detail"]


def test_blob_sha256_mismatch(client, sample):
    ed = LayoutEditor(sample)
    digest = ed.layer_digest(0)
    blob = bytearray(ed.files[f"blobs/sha256/{digest}"])
    blob[0] ^= 0xFF
    ed.set_layer_blob_no_desc_fix(digest, bytes(blob))
    r = unpack(client, ed.to_bytes())
    assert r.status_code == 400
    assert "sha256 mismatch" in r.json()["detail"]


def test_blob_size_mismatch(client, sample):
    ed = LayoutEditor(sample)
    digest = ed.layer_digest(1)
    ed.set_layer_blob_no_desc_fix(
        digest, ed.files[f"blobs/sha256/{digest}"] + b"x"
    )
    r = unpack(client, ed.to_bytes())
    assert r.status_code == 400
    assert "size mismatch" in r.json()["detail"]


def test_diff_id_mismatch(client, sample):
    ed = LayoutEditor(sample)
    cfg = ed.config()
    cfg["rootfs"]["diff_ids"][0] = "sha256:" + "0" * 64
    ed.set_config(cfg)
    r = unpack(client, ed.to_bytes())
    assert r.status_code == 400
    assert "diff_id mismatch" in r.json()["detail"]


def test_layer_count_vs_diff_ids(client, sample):
    ed = LayoutEditor(sample)
    cfg = ed.config()
    cfg["rootfs"]["diff_ids"] = cfg["rootfs"]["diff_ids"][:1]
    ed.set_config(cfg)
    r = unpack(client, ed.to_bytes())
    assert r.status_code == 400
    assert "diff_ids" in r.json()["detail"]


def test_bad_gzip(client, sample):
    ed = LayoutEditor(sample)
    ed.set_layer_blob(0, MT_LAYER_GZ, b"this is not gzip data")
    r = unpack(client, ed.to_bytes())
    assert r.status_code == 400
    assert "gzip" in r.json()["detail"]


def test_gzip_of_non_tar(client, sample):
    payload = gzip.compress(b"not a tar at all", mtime=0)
    ed = LayoutEditor(sample)
    ed.set_layer_blob(0, MT_LAYER_GZ, payload)
    cfg = ed.config()
    cfg["rootfs"]["diff_ids"][0] = f"sha256:{sha256(b'not a tar at all')}"
    ed.set_config(cfg)
    r = unpack(client, ed.to_bytes())
    assert r.status_code == 400
    assert "corrupt layer" in r.json()["detail"]


def test_multiple_manifests_rejected(client, sample):
    ed = LayoutEditor(sample)
    idx = json.loads(ed.files["index.json"])
    idx["manifests"].append(dict(idx["manifests"][0]))
    ed.files["index.json"] = json.dumps(idx).encode()
    r = unpack(client, ed.to_bytes())
    assert r.status_code == 400
    assert "single-manifest" in r.json()["detail"]


def test_not_a_tar(client):
    r = unpack(client, b"this is not a tar file")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# path / link safety
# ---------------------------------------------------------------------------


def _with_layer2(sample, layer_bytes):
    """Replace layer 2 (plain tar) with a crafted one, fixing diff_ids."""
    ed = LayoutEditor(sample)
    ed.set_layer_blob(1, MT_LAYER, layer_bytes)
    cfg = ed.config()
    cfg["rootfs"]["diff_ids"][1] = f"sha256:{sha256(layer_bytes)}"
    ed.set_config(cfg)
    return ed.to_bytes()


def test_dotdot_entry_rejected(client, sample):
    layer = make_layer([("../evil.txt", "file", b"pwned")])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 400
    assert ".." in r.json()["detail"]


def test_absolute_entry_rejected(client, sample):
    layer = make_layer([("/abs-evil.txt", "file", b"pwned")])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 400
    assert "absolute" in r.json()["detail"]


def test_symlink_escape_rejected(client, sample):
    layer = make_layer([
        ("app/link", "symlink", "../../../.."),
        ("app/link/pwn.txt", "file", b"pwned"),
    ])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 400
    assert "escapes" in r.json()["detail"]


def test_write_through_symlink_escape_rejected(client, sample):
    # symlink itself is fine, but a later entry writes through it to ../..
    layer = make_layer([
        ("app/data/x", "symlink", "/../../.."),
        ("app/data/x/pwn.txt", "file", b"pwned"),
    ])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 400


def test_hardlink_escape_rejected(client, sample):
    layer = make_layer([("app/evil", "hardlink", "../../etc/passwd")])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 400


def test_hardlink_missing_target(client, sample):
    layer = make_layer([("app/evil", "hardlink", "no/such/file")])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 400
    assert "not found" in r.json()["detail"]


def test_absolute_symlink_inside_rootfs_ok(client, sample):
    layer = make_layer([
        ("app/motd", "symlink", "/etc/motd"),
        ("app/rel", "symlink", "../etc/motd"),
    ])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 200, r.text
    fs = read_rootfs(r.content)
    assert fs["app/motd"] == ("symlink", "/etc/motd")
    assert fs["app/rel"] == ("symlink", "../etc/motd")


# ---------------------------------------------------------------------------
# whiteout / hardlink semantics with crafted layers
# ---------------------------------------------------------------------------


def test_whiteout_before_same_layer_file(client, sample):
    # marker BEFORE the new file in the same layer: file must still survive
    layer = make_layer([
        ("app/data/.wh.fresh.txt", "file", b""),
        ("app/data/fresh.txt", "file", b"fresh\n"),
    ])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 200, r.text
    fs = read_rootfs(r.content)
    assert fs["app/data/fresh.txt"] == ("file", b"fresh\n")


def test_opaque_keeps_same_layer_files(client, sample):
    layer = make_layer([
        ("app/data/new1.txt", "file", b"n1\n"),
        ("app/data/.wh..wh..opq", "file", b""),
        ("app/data/new2.txt", "file", b"n2\n"),
    ])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 200, r.text
    fs = read_rootfs(r.content)
    # lower content of app/data is gone
    assert "app/data/keep.txt" not in fs
    assert "app/data/remove.txt" not in fs
    # same-layer files survive regardless of marker position
    assert fs["app/data/new1.txt"] == ("file", b"n1\n")
    assert fs["app/data/new2.txt"] == ("file", b"n2\n")


def test_hardlink_pair_preserved_in_output(client, sample):
    # add a fresh hardlink pair in layer 2; output tar must keep the link
    layer = make_layer([
        ("app/data/orig.txt", "file", b"shared\n"),
        ("app/data/alias.txt", "hardlink", "app/data/orig.txt"),
    ])
    r = unpack(client, _with_layer2(sample, layer))
    assert r.status_code == 200, r.text
    fs = read_rootfs(r.content)
    a, b = fs["app/data/orig.txt"], fs["app/data/alias.txt"]
    # the inode is shared: one name is the regular file, the other a
    # hardlink to it (either direction preserves the relationship)
    if a[0] == "file":
        assert a == ("file", b"shared\n")
        assert b == ("hardlink", "app/data/orig.txt")
    else:
        assert b == ("file", b"shared\n")
        assert a == ("hardlink", "app/data/alias.txt")
