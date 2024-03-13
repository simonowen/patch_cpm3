#!/usr/bin/env python3
#
# Patching tool for NABU PC CP/M 3 disk images (v1.2).
#
# Usage: python patch_cpm3.py <disk image>
#
# This script patches NABU CP/M 3 disk images to add a Disk Parameter Block
# (DPB) to the end of the boot sector. The CPMLDR and CPM3.SYS code is then
# patched to read it from there if it wasn't found at the start of track 0.
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
        code = patch_code(code, 0x100, 'C53ED0DD4E0EED793E103D20FDC1C9', 'CPMLDR')
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

    base_addr = (disk[recoffsets[0]+0] - disk[recoffsets[0]+1]) << 8
    if disk[recoffsets[0]+3] != 0:
        print('CPM3.SYS: ignoring second CP/M 3 sub-block')

    nrecords = disk[recoffsets[0]+1] * (256 // reclen)
    recoffsets = list(reversed(recoffsets[2:2+nrecords]))
    code = bytearray().join([read_record(disk, o) for o in recoffsets])

    code = patch_code(code, base_addr, 'F13DC2????676FC9????', 'CPM3.SYS')

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
def patch_code(code, base_addr, last_code, filename):
    start0, end0, wild0 = find_pattern(code, 'FEA128??FEFE28??FE4E20??')
    if start0 is None:
        print(f'{filename}: no code to patch, skipping')
        return code

    exit_off = start0 + 8 + struct.unpack('b', wild0[1])[0]
    fail_off = start0 + 12 + struct.unpack('b', wild0[2])[0]

    read_ret = hex_string(struct.pack('H', base_addr + end0))
    exit_ret = hex_string(struct.pack('H', base_addr + exit_off + 3))
    fail_ret = hex_string(struct.pack('H', base_addr + fail_off + 3))

    _, patch_off, _ = find_pattern(code, last_code)
    patch_jp = bytes.fromhex('C3' + hex_string(struct.pack('H', base_addr + patch_off)))

    exit_code = hex_string(code[exit_off:exit_off+3])
    if exit_code == hex_string(patch_jp):
        print(f'{filename}: already patched')
        return code

    wait_ready = find_pattern(code, 'C506C8DD4E??ED781F3803AFC1C9')[0]
    force_int = find_pattern(code, 'C5{4}3ED0{3}ED79')[0]
    exec_cmd = find_pattern(code, 'C5F5{5}CD????F1DD4E??ED793E0E3D20FDC1C9')[0]
    read_dpb = find_pattern(code, '26022E4E4AED78A428FB')[0]

    if patch_off is None:
        raise RuntimeError(f'{filename}: failed to find patch free space')
    elif wait_ready is None:
        raise RuntimeError(f'{filename}: failed to find wait_ready code')
    elif force_int is None:
        raise RuntimeError(f'{filename}: failed to find force_interrupt code')
    elif exec_cmd is None:
        raise RuntimeError(f'{filename}: failed to find exec_cmd code')
    elif read_dpb is None:
        raise RuntimeError(f'{filename}: failed to find read_dpb code')

    wait_ready = hex_string(struct.pack('H', base_addr + wait_ready))
    force_int = hex_string(struct.pack('H', base_addr + force_int))
    exec_cmd = hex_string(struct.pack('H', base_addr + exec_cmd))
    read_dpb = hex_string(struct.pack('H', base_addr + read_dpb))

    patch = bytes.fromhex(
        f'4B'                   # ld   c,e            ; FDC data port
        f'0D'                   # dec  c              ; FDC sector port
        f'CD{force_int}'        # call force_int      ; stop READ_TRACK command
        f'CD{wait_ready}'       # call wait_ready     ; wait for FDC ready
        f'3E01'                 # ld   a,1            ; sector 1
        f'ED79'                 # out  (c),a          ; select sector for command
        f'3E88'                 # ld   a,&88          ; READ SECTOR
        f'CD{exec_cmd}'         # call exec_cmd       ; execute FDC command
        f'21E103'               # ld   hl,&03e1       ; read up to 4E gap bytes
        f'4A'                   # ld   c,d            ; FDC status port
        f'ED78'                 # in   a,(c)          ; read FDC status
        f'1F'                   # rra                 ; busy?
        f'3018'                 # jr   nc,fail        ; jump if not busy (command finished)
        f'1F'                   # rra                 ; drq?
        f'30F8'                 # jr   nc,wait_data   ; jump back if no data available
        f'4B'                   # ld   c,e            ; FDC data port
        f'ED78'                 # in   a,(c)          ; read (and discard) FDC data
        f'2B'                   # dec  hl             ; decrement byte counter
        f'7C'                   # ld   a,h
        f'B5'                   # or   l
        f'20EF'                 # jr   nz,block_lp    ; loop to read rest
        f'ED78'                 # in   a,(c)          ; re-read, also underrun protection
        f'FE4E'                 # cp   &4E            ; gap byte?
        f'CA{read_ret}'         # jp   z,read_ret     ; if so, jump back to read DPB
        f'{exit_code}'          # 3 bytes of code     ; original code from hook point
        f'C3{exit_ret}'         # jp   exit_ret       ; return to caller to exit
        f'C3{fail_ret}')        # jp   fail_ret       ; return to caller to fail

    known_code = ('3E01C9', 'CD????')
    if not any(find_pattern(bytes.fromhex(exit_code), p)[0] is not None for p in known_code):
        raise RuntimeError(f'{filename}: unconfirmed patch code [{exit_code}]')

    code[exit_off:exit_off+3] = patch_jp
    code[fail_off:fail_off+3] = patch_jp
    code[patch_off:patch_off+len(patch)] = patch
    print(f'{filename}: code patched')

    return code

# Find a byte pattern in a block of code, with optional blocks and wildcards.
def find_pattern(code, hexpattern, start=0):
    code_copy = bytearray(code)
    code_copy[:start] = b'\x00' * start

    pattern = hexpattern.replace('??', '(.)')
    pattern = re.sub(r'{(\d+)}', r'(?:.{\1})?', pattern)
    pattern = re.sub(r'([0-9A-F]{2})(?![}])', r'\\x\1', pattern, flags=re.IGNORECASE)
    matches = list(re.finditer(bytes(pattern, 'ascii'), code_copy, re.MULTILINE|re.DOTALL))

    if (len(matches) == 1):
        return matches[0].start(), matches[0].end(), matches[0].groups()

    if len(matches) > 1:
        raise RuntimeError(f'{hexpattern} matches mutiple code locations')

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

# Convert a byte array to a hex string.
def hex_string(data):
    return ''.join([f'{b:02X}' for b in data])

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
