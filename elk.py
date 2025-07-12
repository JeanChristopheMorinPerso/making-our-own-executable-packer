#!/usr/bin/env python
import os
import mmap
import ctypes
import argparse
import subprocess

import lief

parser = argparse.ArgumentParser(description="ELF runner")
parser.add_argument("file", help="ELF file to run")
args = parser.parse_args()

# with open(args.file, "rb") as fd:
#     raw = fd.read()

print(f"Reading {os.path.abspath(args.file)!r}")

elf = lief.ELF.parse(args.file)

print(f"type: {elf.header.file_type}")
print(f"machine: {elf.header.machine_type}")
print(f"entry_point: 0x{elf.header.entrypoint:08x}")

print("Program headers:")
# Get program headers
for program_header in elf.segments:
    _type = program_header.type
    flags = program_header.flags
    offset = program_header.file_offset
    virtual_address = program_header.virtual_address
    physical_address = program_header.physical_address
    file_size = program_header.physical_size
    mem_size = program_header.virtual_size
    align = program_header.alignment

    print(f"    file {offset:08x}..{offset + file_size:08x} | mem {virtual_address:08x}..{virtual_address + mem_size:08x} | align {align:08x} | {flags:10} {_type}")

# Find all LOAD segments and calculate memory layout
load_segments = [seg for seg in elf.segments if seg.type.name == "LOAD"]
print(f"Found {len(load_segments)} LOAD segments")

# Find entry point segment for disassembly
entry_segment = None
for header in load_segments:
    if elf.entrypoint in range(header.virtual_address, header.virtual_address + header.virtual_size):
        entry_segment = header
        break

if not entry_segment:
    print("segment with entry point not found")
    exit(1)

print(f"entry segment: {entry_segment}")

process = subprocess.Popen(["ndisasm", "-b", "32", "-o", hex(elf.entrypoint), "-"], stdin=subprocess.PIPE)
process.stdin.write(entry_segment.content.tobytes())
process.communicate()

print(f"Executing {os.path.abspath(args.file)!r} in memory")

# Use ctypes to call mmap with MAP_FIXED for exact virtual address mapping
libc = ctypes.cdll.LoadLibrary("libc.so.6")

# mmap syscall constants
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
MAP_FIXED = 0x10
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

# Set up mmap function
mmap_func = libc.mmap
mmap_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
mmap_func.restype = ctypes.c_void_p

if elf.header.file_type == lief.ELF.Header.FILE_TYPE.DYN:
    # picked by fair 4KiB-aligned dice roll
    base = 0x400000
else:
    base = 0x0

# Load each segment at its exact virtual address using MAP_FIXED
mapped_segments = []
for segment in load_segments:
    virtual_address = segment.virtual_address
    mem_size = segment.virtual_size
    content_bytes = segment.content.tobytes()

    if not mem_size:
        continue

    start = virtual_address + base
    aligned_start = start & (~0xfff)
    padding = start - aligned_start
    length = mem_size + padding

    print(f"Mapping segment @ {virtual_address:x}..{virtual_address + mem_size:x} (size: {mem_size:08x})")

    print(f"Addr: 0x{start:x}, Padding: {padding:x}")

    # Use MAP_FIXED to map at exact virtual address
    result = mmap_func(ctypes.c_void_p(aligned_start), length,
                       PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                       -1, 0)
    
    if result == 0xffffffffffffffff:  # MAP_FAILED
        print(f"Failed to map segment @ {aligned_start:08x}")
        exit(1)

    print(f"Copying segment data...")
    # Copy content to mapped memory at correct offset (accounting for padding)
    target_addr = result + padding
    ctypes.memmove(target_addr, content_bytes, len(content_bytes))
    print(f"  Copied to address: {hex(target_addr)} (result + padding {hex(padding)})")

    # Remember code segment address for later debug
    if segment.virtual_address == 0x1000:
        code_segment_addr = result
    mapped_segments.append(result)

# Entry point is the original virtual address since we mapped exactly there
entry_point = elf.entrypoint + base

print(f"Jumping to entry point  @ {entry_point:08x}")

# Create function pointer and execute
func_type = ctypes.CFUNCTYPE(None)
func_ptr = func_type(entry_point)
func_ptr()
