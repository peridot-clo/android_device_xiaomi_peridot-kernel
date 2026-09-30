#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract peridot stock prebuilts from a checked-out Android-Dumps ROM dump."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

DUMP_REVISION = "f643c83fdb689a2db5cd483961c750422ad287f6"
DUMP_URL = "https://gitlab.com/Android-Dumps/poco/peridot.git"
DUMP_BRANCH = "missi-user-16-BP2A.250605.031.A3-OS3.0.4.0.WNPMIXM-release-keys"
ROOT = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def aligned(size, page):
    return (size + page - 1) // page * page


def module_info(data):
    require(data[:6] == b"\x7fELF\x02\x01" and
            struct.unpack_from("<H", data, 18)[0] == 183, "Not an AArch64 ELF module")
    values = re.findall(rb"\x00vermagic=([^\x00]+)", data)
    require(len(values) == 1, "Missing or ambiguous module vermagic")
    return values[0].decode()


def validate(root):
    manifest = json.loads((root / "prebuilts.json").read_text())
    for name, entry in manifest["files"].items():
        data = (root / name).read_bytes()
        require(digest(data) == entry["sha256"], f"Hash mismatch: {name}")
        if name.endswith(".ko"):
            require(module_info(data) == entry["vermagic"], f"Changed module: {name}")
    for part in ("system_dlkm", "vendor_dlkm", "vendor_ramdisk"):
        for load in (root / part).glob("modules.load*"):
            names = load.read_text().split()
            require(len(names) == len(set(names)), f"Duplicate entries: {load}")
            require(all((root / part / name).is_file() for name in names),
                    f"Missing load-list module: {load}")
    print("Verified", len(manifest["files"]), "prebuilt files and all module load lists")


def extract(dump, output):
    require(not (output / "prebuilts.json").exists(), "Output already has prebuilts; use a fresh directory")
    revision = subprocess.check_output(["git", "-C", str(dump), "rev-parse", "HEAD"], text=True).strip()
    require(revision == DUMP_REVISION, f"Unexpected dump revision: {revision}")
    files = {}
    inputs = {}

    def read(name):
        data = (dump / name).read_bytes()
        # Check each checked-out source against the pinned Git blob, not just HEAD.
        oid = subprocess.check_output(["git", "-C", str(dump), "rev-parse",
                                       f"{revision}:{name}"], text=True).strip()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(actual == oid, f"Source differs from pinned dump: {name}")
        require(not data.startswith(b"version https://git-lfs.github.com/spec/"), f"LFS pointer: {name}")
        inputs[name] = {"git_blob": oid, "sha256": digest(data)}
        return data

    def put(name, data, source, transformation="none"):
        path = output / name
        require(not path.exists(), f"Refusing to overwrite {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        files[name] = {"sha256": digest(data), "size": len(data), "source": source,
                       "transformation": transformation}
        if name.endswith(".ko"):
            files[name]["vermagic"] = module_info(data)

    boot = read("boot.img")
    require(boot[:8] == b"ANDROID!" and u32(boot, 40) == 4, "Expected Android boot header v4")
    kernel = boot[4096:4096 + u32(boot, 8)]
    require(kernel == read("boot/kernel"), "Unpacked kernel differs from boot.img")
    require(kernel[56:60] == b"ARM\x64", "Expected uncompressed ARM64 Image")
    banner = re.search(rb"Linux version ([^ ]+)[^\x00\n]+", kernel).group().decode()
    release = banner.split()[2]
    put("Image", kernel, "boot.img", "extract kernel payload; matches boot/kernel")
    put("kernel.release", (release + "\n").encode(), "boot/kernel", "extract Linux version banner")
    put(".config", read("ikconfig"), "ikconfig")

    vendor = read("vendor_boot.img")
    require(vendor[:8] == b"VNDRBOOT" and u32(vendor, 8) == 4, "Expected vendor_boot header v4")
    page = u32(vendor, 12)
    require(page == 4096, "Unexpected vendor_boot page size")
    offset = aligned(u32(vendor, 2096), page) + aligned(u32(vendor, 24), page)
    dtbs = vendor[offset:offset + u32(vendor, 2100)]
    index = 0
    while dtbs:
        require(dtbs[:4] == b"\xd0\x0d\xfe\xed", "Malformed concatenated DTB")
        size = struct.unpack_from(">I", dtbs, 4)[0]
        require(40 <= size <= len(dtbs), "DTB size outside vendor_boot payload")
        index += 1
        put(f"dtbs/{index:02d}-peridot.dtb", dtbs[:size], "vendor_boot.img", "split DTB payload in original order")
        dtbs = dtbs[size:]
    require(index == 2, "Expected two Cliffs base DTBs")
    dtbo = read("dtbo.img")
    require(dtbo[:4] == b"\xd7\xb7\xab\x1e", "Invalid Android DTBO image")
    total, header, entry_size, count, entries = struct.unpack_from(">5I", dtbo, 4)
    require(total <= len(dtbo) and header >= 32 and entry_size >= 32 and count == 2,
            "Unexpected DTBO table")
    for i in range(count):
        size, off = struct.unpack_from(">II", dtbo, entries + i * entry_size)
        require(off + size <= total and dtbo[off:off+4] == b"\xd0\x0d\xfe\xed", "Invalid DTBO entry")
    put("dtbs/dtbo.img", dtbo, "dtbo.img")

    module_dirs = {"vendor_ramdisk": "vendor_boot/ramdisk/lib/modules",
                   "vendor_dlkm": "vendor_dlkm/lib/modules",
                   "system_dlkm": "system_dlkm/flatten/lib/modules"}
    for dest, source in module_dirs.items():
        require((dump / source / "modules.load").is_file(), f"Missing {source}")
        names = subprocess.check_output(["git", "-C", str(dump), "ls-tree", "-r",
                                         "--name-only", revision, "--", source], text=True).splitlines()
        for name in names:
            path = dump / name
            require(path.is_file() and not path.is_symlink(), f"Unexpected module directory entry: {path}")
            name = path.relative_to(dump).as_posix()
            data = read(name)
            transformation = "none"
            if path.name.startswith("modules.load"):
                names = data.decode().split()
                require(all(Path(n).name == n and n.endswith(".ko") for n in names), "Expected flat module names")
                data = ("\n".join(dict.fromkeys(names)) + "\n").encode()
                transformation = "deduplicate load entries preserving first occurrence"
            put(f"{dest}/{path.name}", data, name, transformation)

    # Recovery carries six audio modules that differ from vendor_dlkm. Keep
    # these in their own directory; the device chooses them only for recovery.
    recovery = sorted((dump / "recovery/ramdisk/vendor/lib/modules").glob("*.ko"))
    require(len(recovery) == 6, "Expected all six stock recovery audio modules")
    for path in recovery:
        data = read(path.relative_to(dump).as_posix())
        put(f"recovery/{path.name}", data, path.relative_to(dump).as_posix())

    # AOSPA expects these paths even for binary-only imports. No symbol data is invented.
    for name in ("System.map", "Module.symvers", "techpack.built"):
        put(name, b"", None, "AOSPA prebuilt-only placeholder; not kernel build output")
    manifest = {"dump_url": DUMP_URL, "dump_branch": DUMP_BRANCH, "dump_revision": revision,
                "linux_banner": banner, "inputs": inputs, "files": files,
                "notes": ["Stock GKI and vendor modules have different vermagic releases; retained unchanged.",
                          "Stock zram/zsmalloc differ between system_dlkm and vendor_ramdisk; do not flatten across partitions.",
                          "Six recovery audio modules differ from vendor_dlkm and are kept separately.",
                          "System.map and Module.symvers are empty compatibility placeholders.",
                          "No userspace headers can be reconstructed from these boot images."]}
    (output / "prebuilts.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    validate(output)
    print(banner)
    for part in module_dirs:
        print(part, len(list((output / part).glob("*.ko"))), "modules")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path, nargs="?")
    parser.add_argument("--output", type=Path, default=ROOT)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        validate(args.output)
    elif args.dump:
        extract(args.dump.resolve(), args.output.resolve())
    else:
        parser.error("provide a checked-out dump or --verify")
