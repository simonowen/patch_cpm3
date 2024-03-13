#!/usr/bin/env python3
#
# Patching tool for NABU PC CP/M 3 disk images (v1.1).
#
# Usage: python patch_cpm3.py <disk image>
#
# This script patches NABU CP/M 3 disk images to move the Disk Parameter Block
# (DPB) to the end of the boot sector. The cpmldr and CPM3.SYS code is then
# patched to read it from there instead.
#
# The patched image is saved out to a new file with a '_patched' suffix.
#
# Homepage: https://github.com/simonowen/patch_cpm3

import os
import re
import struct
import argparse

diskdefs = {
    # size:[ tracks, blocksize, maxdir, DPB ]
    204800:[ 40,1024, 96, '04050607002800030700C2005F00E000001801000307'],
    409600:[ 80,2048,192, '04050607012800040F01C400BF00E000003001000307'],
    819200:[160,2048,384, '04050607022800040F008C017F01FC00006101000307'] }

# Common parameters for all NABU disk images.
seclen = 1024
sectrk = 5
skew = 2
boottrk = 1
reclen = 128

# Read and patch the given disk image, outputting the patched image to a new file.
def main():
    imgsize = os.path.getsize(args.file)
    if not imgsize in diskdefs:
        valid = ', '.join([str(s) for s in sorted(diskdefs.keys())])
        raise RuntimeError(f'Invalid disk image size ({imgsize}), supported sizes: {valid}')

    global tracks, blocksize, maxdir, dpbhex
    tracks, blocksize, maxdir, dpbhex = diskdefs[imgsize]

    print(f'Reading: {args.file}')
    with open(args.file, 'rb') as f:
        disk = bytearray(f.read())

    disk_before = bytes(disk)
    disk = patch_boot_sector(disk)
    disk = patch_boot_loader(disk)
    disk = patch_cpm3_sys(disk)

    if disk != disk_before:
        basename, ext = os.path.splitext(args.file)
        filename = f'{basename}_patched{ext}'
        with open(filename, 'wb') as f:
            f.write(bytes(disk))
        print(f'Written to {filename}')

# Add DPB to end of boot sector, prefixed by 4E bytes to pad up to 32 bytes.
def patch_boot_sector(disk):
    block_len = 32
    dpb_block = bytes([0x4e] * (block_len - len(bytes.fromhex(dpbhex)))) + bytes.fromhex(dpbhex)

    old_block = disk[seclen-block_len:seclen]
    if old_block == dpb_block:
        print('Boot sector: already patched')
        return disk

    if old_block == bytes(old_block[0:1] * block_len):
        pass # allow common filler
    elif not any((x+i) & 0xff != old_block[0] for x, i in enumerate(old_block)):
        pass # allow decrementing pattern
    elif args.force:
        pass # patch if forced
    else:
        raise RuntimeError('Boot sector: unrecognised, will not update without --force option')

    disk[seclen-block_len:seclen] = dpb_block
    print('Boot sector: added DPB')

    return disk

# Patch CPMLDR to read DPB from end of first sector.
def patch_boot_loader(disk):
    start, end = seclen, seclen * sectrk
    code = disk[start:end]

    if code == bytes(code[0:1] * (end - start)):
        print('CPMLDR: not found, skipping')
    else:
        code = patch_code(code, 'CPMLDR')
        disk[start:end] = code

    return disk

# Patch CPM3.SYS to read DPB from end of first sector.
def patch_cpm3_sys(disk):
    entry = find_file(disk, 'cpm3.sys')
    if entry is None:
        print('CPM3.SYS: file not found, skipping')
        return disk

    nrecords = entry[15]
    blockidx = list(filter(lambda n: n > 0, struct.unpack('16B', entry[16:32])))
    recoffsets = [block_offset(b, r) for b in blockidx for r in range(blocksize // reclen)][:nrecords]

    if disk[recoffsets[0]+3] != 0:
        print('CPM3.SYS: ignoring second CP/M 3 sub-block')

    nrecords = disk[recoffsets[0]+1] * (256 // reclen)
    recoffsets = list(reversed(recoffsets[2:2+nrecords]))
    code = bytearray().join([read_record(disk, o) for o in recoffsets])

    code = patch_code(code, 'CPM3.SYS')

    for r in range(nrecords):
        disk[recoffsets[r]:recoffsets[r]+reclen] = code[r*reclen:(r+1)*reclen]

    return disk

# Find a named CP/M file entry in the directory.
def find_file (disk, filename):
    name, ext = filename.upper().split('.')
    name_match = bytes(f'{name:8s}{ext:3s}', 'ascii')

    dir_entry_len = 32
    dir_offset = boottrk * sectrk * seclen

    for i in range(maxdir):
        entry_offset = dir_offset + i * dir_entry_len
        entry = disk[entry_offset:entry_offset+dir_entry_len]
        if entry[0] != 0xe5 and entry[1:12] == name_match:
            return entry

    return None

# Patch the DPB reading in the given block of code.
def patch_code(code, filename):
    # Find  ld a,READ_TRACK ; CALL exec_fdc_cmd  at start of patch area.
    start0, end0, wild0 = find_pattern(code, '3EE0CD????4A')
    if start0 is None:
        start0, end0, wild0 = find_pattern(code, '4B0D3E01ED793E88CD')
        if start0 is not None:
            print(f'{filename}: already patched')
        else:
            print(f'{filename}: no code to patch, skipping')
        return code

    exec_fdc_cmd = ''.join([b.hex().upper() for b in wild0])

    # Find next  CALL read_fdc_data ; jr exit  at end of patch.
    start1, end1, _ = find_pattern(code, 'CD????18??', end0)
    if start1 is None:
        print(f'{filename}: end of patch not found, skipping')
        return code

    fail_offset = end1 - start0 - 21
    done_offset = start1 - start0 - 32

    patch = bytes.fromhex(
        f'4B'                   # ld   c,e            ; FDC data port
        f'0D'                   # dec  c              ; FDC sector port
        f'3E01'                 # ld   a,1            ; sector 1
        f'ED79'                 # out  (c),a          ; select sector for command
        f'3E88'                 # ld   a,&88          ; READ SECTOR
        f'CD{exec_fdc_cmd}'     # call exec_fdc_cmd   ; execute FDC command
        f'261F'                 # ld   h,31           ; 31 blocks...
        f'0620'                 # ld   b,32           ; ...of 32 bytes
        f'4A'                   # ld   c,d            ; FDC status port
        f'ED78'                 # in   a,(c)          ; read FDC status
        f'1F'                   # rra                 ; busy?
        f'30{fail_offset:02X}'  # jr   nc,exit        ; jump if not busy (command finished)
        f'1F'                   # rra                 ; drq?
        f'30F8'                 # jr   nc,wait_data   ; jump back if no data available
        f'4B'                   # ld   c,e            ; FDC data port
        f'ED78'                 # in   a,(c)          ; read (and discard) FDC data
        f'10F2'                 # djnz block_lp       ; loop to finish block of 32
        f'25'                   # dec  h              ; next block
        f'28{done_offset:02X}'  # jr   z,continue     ; jump if all done (to CALL after patch)
        f'18EB')                # jr   blocks_lp      ; complete remaining blocks

    target_size = start1 - start0
    if target_size < len(patch):
        print('{filename}: patch target is too small, skipping')
    elif target_size >= 0x80:
        print('{filename}: patch target is suspiciously large, skipping')
    else:
        patch = patch + b'\x00' * (target_size - len(patch))
        code[start0:start1] = patch
        print(f'{filename}: code patched')

    return code

# Find a byte pattern in a block of code, with wildcard matching.
def find_pattern(code, hexpattern, start=0):
    code_copy = bytearray(code)
    code_copy[:start] = b'\x00' * start

    pattern = ''.join(['(.)' if b == '??' else f'\\x{b}' for b in re.findall('..', hexpattern)])
    matches = list(re.finditer(bytes(pattern, 'ascii'), code_copy, re.MULTILINE))

    if (len(matches) == 1):
        return matches[0].start(), matches[0].end(), matches[0].groups()

    if len(matches) > 1:
        print(f'warning: {hexpattern} matches mutiple locations, patch is too generic')
    return None, None, None

# Calculate the disk offset of the given CP/M block number and sub-record.
def block_offset(blockno, record=0):
    if not 'skewtab' in globals():
        global skewtab
        skewtab = []
        for s in range(sectrk):
            skewtab.append(next(filter(lambda n: n not in skewtab, [(i*skew + i//sectrk) % sectrk for i in range(sectrk * skew)])))

    recoffset = record * reclen
    lba = blockno * (blocksize // seclen) + sectrk * boottrk + (recoffset // seclen)
    track, sector = lba // sectrk, lba % sectrk
    offset = (track * sectrk + skewtab[sector]) * seclen + (recoffset % seclen)
    return offset

# Read a 128-byte CP/M record from the given offset of a disk image.
def read_record(disk, offset):
    return disk[offset:offset+reclen]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Patch DPB reading in NABU PC CP/M 3 disk images.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-f', '--force', action='store_true', help='Force patching boot sector')
    parser.add_argument('file')
    try:
        global args
        args = parser.parse_args()
        main()
    except Exception as e:
        print(e)
        exit(1)
