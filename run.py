#!/usr/bin/env python
import mmap
import ctypes

# Load the system C library to access mprotect function
libc = ctypes.cdll.LoadLibrary("libc.so.6")

# Create buffer with the string we want to print
string_data = b"Hello, world!\n"  # 14 bytes
buffer = ctypes.create_string_buffer(string_data, 4096)  # 4KB buffer

# Get the memory address of our buffer
addr = ctypes.addressof(buffer)

# Construct x86-64 assembly code that will:
# 1. Call write() syscall to print the string
# 2. Call exit() syscall to terminate
assembly = (
    b"\x48\xc7\xc7\x01\x00\x00\x00"      # mov rdi, 1 (file descriptor: stdout)
    + b"\x48\xbe" + addr.to_bytes(8, 'little')  # mov rsi, addr (pointer to string)
    + b"\x48\xc7\xc2\x0e\x00\x00\x00"    # mov rdx, 14 (number of bytes to write)
    + b"\x48\xc7\xc0\x01\x00\x00\x00"    # mov rax, 1 (syscall number for write)
    + b"\x0f\x05"                        # syscall (invoke write system call)
    + b"\x48\x31\xff"                    # xor rdi, rdi (set exit code to 0)
    + b"\x48\xc7\xc0\x3c\x00\x00\x00"    # mov rax, 60 (syscall number for exit)
    + b"\x0f\x05"                        # syscall (invoke exit system call)
)

# Place assembly code in buffer after the string (overwrite bytes 14 onwards)
buffer[14:14+len(assembly)] = assembly
print(f"instructions @ 0x{addr:0x}")

# Find the page boundary (4KB aligned) that contains our buffer
# This is needed because mprotect works on page boundaries
page_addr = addr & (~0xFFF)  # Clear lower 12 bits to align to 4KB boundary
print(f"page @ 0x{page_addr:0x}")

# Set up the mprotect function with proper type signatures
mprotect_function = libc.mprotect
mprotect_function.restype = ctypes.c_int  # Returns int
mprotect_function.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]  # (addr, size, prot)

# Make the memory page executable (readable, writable, and executable)
print("making page executable...")
ret = mprotect_function(page_addr, 0x1000, mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
print("mprotect ret:", ret)

if ret == 0:  # mprotect succeeded
    # Create a function pointer type that takes no arguments and returns nothing
    MyFunctionPointerType = ctypes.CFUNCTYPE(None)
    
    # Create function pointer pointing to our assembly code (skip the 14-byte string)
    f = MyFunctionPointerType(addr + 14)
    
    print("jumping...")
    f()  # Execute our assembly code
    print("after jump")  # This won't print because assembly calls exit()
else:
    print("mprotect failed")
