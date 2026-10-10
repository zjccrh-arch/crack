"""Patch the fixed vendor baseline, sign on macOS, and rebuild complete DEB."""
import argparse
import copy
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import struct
import subprocess
import tempfile
import tarfile

SOURCE_SHA = "07130c2b9110a15a93b2c000ea6a90a888be98d182f2c97c1f5509ed80ed8dfa"
VERSION = "0.3.7-15+unlocked6"
PATCH = bytes.fromhex("20008052c0035fd6")
TARGETS = {
    "var/jb/Library/MobileSubstrate/DynamicLibraries/SwipeDeck.dylib":
        {0: 0x7AAF0, 0x80000002: 0x80E1C},
    "var/jb/Library/PreferenceBundles/SwipeDeckPrefs.bundle/SwipeDeckPrefs":
        {0: 0x82714, 0x80000002: 0x89108},
}
STATE_ENTRIES = {
    "var/jb/Library/MobileSubstrate/DynamicLibraries/SwipeDeck.dylib":
        {0: 0x7A62C, 0x80000002: 0x8093C},
    "var/jb/Library/PreferenceBundles/SwipeDeckPrefs.bundle/SwipeDeckPrefs":
        {0: 0x82250, 0x80000002: 0x88C28},
}

def ar_parse(raw):
    assert raw[:8] == b"!<arch>\n"
    pos, result = 8, {}
    while pos < len(raw):
        header = raw[pos:pos + 60]
        assert len(header) == 60 and header[58:] == b"`\n"
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58])
        pos += 60
        assert pos + size <= len(raw)
        result[name] = raw[pos:pos + size]
        pos += size + (size & 1)
    assert pos == len(raw)
    return result

def ar_member(name, body):
    head = (name.encode().ljust(16, b" ") + b"0           "
            + b"0     " + b"0     " + b"100644  "
            + str(len(body)).encode().ljust(10, b" ") + b"`\n")
    assert len(head) == 60
    return head + body + (b"\n" if len(body) & 1 else b"")

def archive_read(body):
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as tar:
        members = tar.getmembers()
        files = {m.name.lstrip("./"): tar.extractfile(m).read()
                 for m in members if m.isfile()}
    return members, files

def archive_build(members, files, compression):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        for original in members:
            member = copy.copy(original)
            if member.isfile():
                data = files[member.name.lstrip("./")]
                member.size = len(data)  # Never truncate control or changed binaries.
                tar.addfile(member, io.BytesIO(data))
            else:
                tar.addfile(member)
    if compression == "gz":
        return gzip.compress(stream.getvalue(), compresslevel=9, mtime=0)
    return lzma.compress(stream.getvalue(), format=lzma.FORMAT_ALONE, preset=9)

def slices(fat):
    assert struct.unpack_from(">I", fat)[0] == 0xCAFEBABE
    count = struct.unpack_from(">I", fat, 4)[0]
    assert count == 2
    for i in range(count):
        cpu, subtype, offset, size, align = struct.unpack_from(">5I", fat, 8 + i * 20)
        assert cpu == 0x100000C and offset + size <= len(fat)
        yield i, subtype, offset, size, fat[offset:offset + size]

def verify_codeslots(raw):
    magic, cpu, subtype, kind, ncmds = struct.unpack_from("<5I", raw)
    assert magic == 0xFEEDFACF and kind in (6, 8)
    pos, dirs = 32, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<2I", raw, pos)
        assert size >= 8 and pos + size <= len(raw)
        if cmd == 0x1D:
            off, length = struct.unpack_from("<2I", raw, pos + 8)
            assert off > 0 and length > 0 and off + length == len(raw)
            blob = raw[off:off + length]
            magic, total, count = struct.unpack_from(">3I", blob)
            assert magic == 0xFADE0CC0 and total <= length
            for i in range(count):
                slot_type, bo = struct.unpack_from(">2I", blob, 12 + i * 8)
                if struct.unpack_from(">I", blob, bo)[0] != 0xFADE0C02:
                    continue
                _, cdlen, ver, flags, hoff, ident, special, slots, limit = struct.unpack_from(">9I", blob, bo)
                hs, ht, platform, pageshift = struct.unpack_from(">4B", blob, bo + 36)
                fn = {1: hashlib.sha1, 2: hashlib.sha256, 3: hashlib.sha256, 4: hashlib.sha384}[ht]
                page = 1 << pageshift
                assert limit <= off and bo + cdlen <= len(blob)
                assert slots == (limit + page - 1) // page
                for k in range(slots):
                    expected = blob[bo + hoff + k * hs:bo + hoff + (k + 1) * hs]
                    actual = fn(raw[k * page:min((k + 1) * page, limit)]).digest()[:hs]
                    assert expected == actual, (subtype, k, "signature page mismatch")
                dirs.append({"hash_type": ht, "code_slots": slots})
        pos += size
    assert dirs
    return dirs

def patch_fat(fat, name):
    result = bytearray(fat)
    offsets = TARGETS[name]
    for i, subtype, offset, size, raw in slices(fat):
        entry = offsets[subtype]
        expected = bytes.fromhex("ffc303d1fc6f09a9" if subtype == 0 else "7f2303d5ffc303d1")
        assert raw[entry:entry + 8] == expected, (name, subtype, "unexpected baseline")
        result[offset + entry:offset + entry + 8] = PATCH
        state = STATE_ENTRIES[name][subtype]
        expected_state = bytes.fromhex("ffc303d1fa670aa9" if subtype == 0 else "7f2303d5ffc303d1")
        assert result[offset + state:offset + state + 8] == expected_state
    return bytes(result)

def build(source, output):
    original = source.read_bytes()
    assert hashlib.sha256(original).hexdigest() == SOURCE_SHA, "unexpected input"
    members = ar_parse(original)
    cm, controls = archive_read(members["control.tar.gz"])
    dm, payload = archive_read(members["data.tar.lzma"])
    report = []
    with tempfile.TemporaryDirectory(prefix="swipedeck-sign-") as temp:
        for path in TARGETS:
            target = Path(temp) / Path(path).name
            target.write_bytes(patch_fat(payload[path], path))
            # Preserve load-command/signature layout for RootHide conversion.
            subprocess.run(["ldid", "-S", str(target)], check=True)
            signed = target.read_bytes()
            for i, sub, off, size, raw in slices(signed):
                entry = TARGETS[path][sub]
                assert raw[entry:entry + 8] == PATCH
                state = STATE_ENTRIES[path][sub]
                expected_state = bytes.fromhex("ffc303d1fa670aa9" if sub == 0 else "7f2303d5ffc303d1")
                assert raw[state:state + 8] == expected_state, "signer changed initialization entry"
                report.append({"path": path, "subtype": hex(sub), "entry": hex(entry),
                               "code_directories": verify_codeslots(raw)})
            payload[path] = signed
    controls["control"] = controls["control"].decode("utf-8").replace(
        "Version: 0.3.7-15\n", "Version: " + VERSION + "\n").encode()
    assert controls["control"].endswith(b"Installed-Size: 5496\n")
    postinst = controls["postinst"].decode("utf-8")
    assert postinst.count("exit 0") == 1
    seed = '''# Preserve existing activation data; seed only the plugin's own store.
# RootHide runs this script inside its bootstrap filesystem view.
set -eu
if [ ! -e "$PREFDIR/activation.dat" ]; then
    umask 077
    seed_tmp="$PREFDIR/activation.dat.direct.$$"
    trap 'rm -f "$seed_tmp"' EXIT HUP INT TERM
    printf '%064d' 0 | tr '0' '1' > "$seed_tmp"
    test "$(wc -c < "$seed_tmp" | tr -d ' ')" = 64
    chown mobile:mobile "$seed_tmp"
    chmod 600 "$seed_tmp"
    mv "$seed_tmp" "$PREFDIR/activation.dat"
    trap - EXIT HUP INT TERM
fi
'''
    controls["postinst"] = postinst.replace("exit 0", seed + "\nexit 0").replace(
        "@PACKAGE_VERSION@", VERSION).encode("utf-8")
    controls["md5sums"] = "".join(
        hashlib.md5(data).hexdigest() + "  " + path + "\n"
        for path, data in sorted(payload.items())
    ).encode("utf-8")
    if not any(m.name.lstrip("./") == "md5sums" for m in cm):
        member = tarfile.TarInfo("md5sums")
        member.mode = 0o644
        cm.append(member)
    ct = archive_build(cm, controls, "gz")
    dt = archive_build(dm, payload, "lzma")
    assert dt[:5] == bytes.fromhex("5d00000004")
    decoded = lzma.decompress(dt, format=lzma.FORMAT_ALONE)
    with tarfile.open(fileobj=io.BytesIO(decoded)) as tar:
        for path in TARGETS:
            assert tar.extractfile(tar.getmember(path)).read() == payload[path]
    result = b"!<arch>\n"
    for name, body in [("debian-binary", b"2.0\n"), ("control.tar.gz", ct), ("data.tar.lzma", dt)]:
        result += ar_member(name, body)
    output.mkdir(parents=True, exist_ok=True)
    deb = output / ("SwipeDeck-" + VERSION + ".deb")
    deb.write_bytes(result)
    digest = hashlib.sha256(result).hexdigest()
    (output / "SHA256SUMS").write_text(digest + "  " + deb.name + "\n")
    (output / "VERIFY.json").write_text(json.dumps({"source_sha256": SOURCE_SHA,
        "sha256": digest, "version": VERSION, "size": len(result), "slices": report}, indent=2))
    print(json.dumps(report, indent=2))
    print("SHA256=" + digest)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(args.input, args.output)
