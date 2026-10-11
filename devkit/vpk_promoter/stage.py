#!/usr/bin/env python3
"""Stage a VPK so the Vita installs it through its own promoter, over host0:.

promoter.bin (main.c, built with VitaSDK: cmake -S devkit/vpk_promoter -B BUILD) copies
host0:/package to ux0:data/vpk-promoter-package and promotes it with
scePromoterUtilityPromotePkgWithRif, as VitaShell does; the shell database is not edited.
The package needs a package header (sce_sys/package/head.bin; without it the promotion fails
with 0x8010111C): this writes one from VitaShell's resources/head.bin, with the VPK's title ID
in its content ID and the hashes redone.

    devkit/vpk_promoter/stage.py --vpk app.vpk --head-template VitaShell/resources/head.bin \\
        --promoter BUILD/promoter.bin --out HOST0
    devkit/deci4p_host.py --usb --host0 HOST0 --launch host0:/promoter.bin

The promoter prints "[vpk-promoter] promote: 0x00000000" and "[vpk-promoter] finished" on the
Vita's TTY (devkit/devkit_console.py) and exits. To update an installed app, unzip the new VPK
over HOST0/package and stage again: the header must stay.
"""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import struct
import sys
import zipfile


def extract_vpk(vpk, destination, required_files):
    destination.mkdir(parents=True)
    with zipfile.ZipFile(vpk) as archive:
        names = set()
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError(f'unsafe VPK path: {member.filename}')
            if member.is_dir():
                continue
            names.add(member.filename)
            output = destination.joinpath(*path.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, output.open('wb') as target:
                shutil.copyfileobj(source, target)
    missing = required_files - names
    if missing:
        raise ValueError(f'VPK is missing: {", ".join(sorted(missing))}')


def package_hash(data):
    digest = hashlib.sha1(data).digest()
    seed = digest[4:12] * 2 + digest[12:17] + digest[1:4]
    return hashlib.sha1(seed + seed[16:24] + bytes(32)).digest()[:16]


def sfo_title_id(path):
    """TITLE_ID from a param.sfo (PSF: header, index table, key and data tables)."""
    data = path.read_bytes()
    magic, _, keys, values, count = struct.unpack_from('<4sIIII', data)
    if magic != b'\0PSF':
        sys.exit(f'{path}: not a param.sfo')
    for index in range(count):
        key, _, length, _, offset = struct.unpack_from('<HHIII', data, 20 + index * 16)
        name = data[keys + key:data.index(b'\0', keys + key)]
        if name == b'TITLE_ID':
            return data[values + offset:values + offset + length].rstrip(b'\0')
    sys.exit(f'{path}: no TITLE_ID')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--vpk', type=Path, required=True)
    parser.add_argument('--head-template', type=Path, required=True)
    parser.add_argument('--promoter', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    package = args.out / 'package'
    extract_vpk(args.vpk, package, {'sce_sys/param.sfo', 'eboot.bin'})
    header = bytearray(args.head_template.read_bytes())
    if len(header) < 0x100:
        parser.error('package header template is truncated')
    title_id = sfo_title_id(package / 'sce_sys/param.sfo')
    content_id = b'EP9000-' + title_id + b'_00-0000000000000000'
    header[0x30:0x60] = content_id.ljust(48, b'\0')
    length = struct.unpack_from('>I', header, 0xd0)[0]
    offset = struct.unpack_from('>I', header, 8)[0]
    info_length = struct.unpack_from('>I', header, 0x10)[0] - 64
    output = struct.unpack_from('>I', header, 0xd4)[0]
    total = struct.unpack_from('>I', header, 0xe8)[0]
    if min(info_length, length, total) < 0 or max(length + 16, offset + info_length, output + 16, total + 16) > len(header):
        parser.error('package header template offsets are invalid')
    header[length:length + 16] = package_hash(header[:length])
    header[output:output + 16] = package_hash(header[offset:offset + info_length])
    header[total:total + 16] = package_hash(header[:total])
    metadata = package / 'sce_sys/package'
    metadata.mkdir(parents=True, exist_ok=True)
    (metadata / 'head.bin').write_bytes(header)
    shutil.copy2(args.promoter, args.out / 'promoter.bin')
    print(args.out.resolve())


if __name__ == '__main__':
    main()
