#!/usr/bin/env python3
"""
SyscallGuard Demo — Attack Simulation Script
==============================================
This standalone script directly invokes dangerous Linux syscalls
to simulate a supply chain attack. It runs OUTSIDE pytest so there
are no test-discovery issues.

When run under strace, these syscalls appear in the captured log
and get detected by SyscallGuard's diff engine as novel Tier 1 threats.

Triggered syscalls:
  - memfd_create   (fileless malware)
  - ptrace         (process injection)
  - shmget/shmat   (shared memory manipulation)
  - personality    (ASLR bypass)
  - keyctl         (credential theft)

Usage:
  sudo strace -f -o /tmp/attack-trace.log python syscallguard/demo/attack_simulation.py
"""

import ctypes
import ctypes.util
import os
import sys


def get_libc():
    """Get a handle to libc for direct syscall invocation."""
    libc_name = ctypes.util.find_library('c')
    return ctypes.CDLL(libc_name or "libc.so.6", use_errno=True)


def attack_memfd_create():
    """Trigger memfd_create — fileless malware indicator."""
    print("  [1/5] memfd_create (fileless malware)...", end=" ")
    try:
        fd = os.memfd_create("suspicious_payload")
        os.write(fd, b"SIMULATED_MALWARE_BINARY_PAYLOAD_DATA" * 100)
        os.close(fd)
        print("✅ triggered")
    except Exception as e:
        # Fallback: use syscall number directly (319 on x86_64)
        try:
            libc = get_libc()
            fd = libc.syscall(319, b"payload", 0)
            if fd >= 0:
                os.close(fd)
            print("✅ triggered (via syscall)")
        except Exception as e2:
            print(f"⚠️ failed: {e2}")


def attack_ptrace():
    """Trigger ptrace — process injection indicator."""
    print("  [2/5] ptrace (process injection)...", end=" ")
    try:
        libc = get_libc()
        # PTRACE_TRACEME = 0 — trace self (harmless but logged by strace)
        result = libc.ptrace(0, 0, None, None)
        print(f"✅ triggered (result={result})")
    except Exception as e:
        # Fallback: use syscall number directly (101 on x86_64)
        try:
            libc = get_libc()
            libc.syscall(101, 0, 0, 0, 0)
            print("✅ triggered (via syscall)")
        except Exception as e2:
            print(f"⚠️ failed: {e2}")


def attack_shmget():
    """Trigger shmget/shmat — shared memory IPC exfiltration."""
    print("  [3/5] shmget+shmat (shared memory)...", end=" ")
    try:
        libc = get_libc()
        # IPC_PRIVATE=0, size=4096, IPC_CREAT|0666 = 0o1666
        shmid = libc.shmget(0, 4096, 0o1666)
        if shmid >= 0:
            libc.shmat.restype = ctypes.c_void_p
            addr = libc.shmat(shmid, None, 0)
            if addr and addr != ctypes.c_void_p(-1).value:
                libc.shmdt(ctypes.c_void_p(addr))
            # IPC_RMID = 0
            libc.shmctl(shmid, 0, None)
            print(f"✅ triggered (shmid={shmid})")
        else:
            print(f"⚠️ shmget returned {shmid}")
    except Exception as e:
        print(f"⚠️ failed: {e}")


def attack_personality():
    """Trigger personality — ASLR bypass indicator."""
    print("  [4/5] personality (ASLR bypass)...", end=" ")
    try:
        libc = get_libc()
        # 0xffffffff = read current personality (no change, safe)
        current = libc.personality(0xffffffff)
        print(f"✅ triggered (personality={current})")
    except Exception as e:
        # Fallback: syscall 135 on x86_64
        try:
            libc = get_libc()
            libc.syscall(135, 0xffffffff)
            print("✅ triggered (via syscall)")
        except Exception as e2:
            print(f"⚠️ failed: {e2}")


def attack_keyctl():
    """Trigger keyctl — credential theft indicator."""
    print("  [5/5] keyctl (credential theft)...", end=" ")
    try:
        libc = get_libc()
        # KEYCTL_GET_KEYRING_ID=0, KEY_SPEC_SESSION_KEYRING=-3
        result = libc.syscall(250, 0, -3, 0)
        print(f"✅ triggered (result={result})")
    except Exception as e:
        print(f"⚠️ failed: {e}")


def main():
    print("=" * 60)
    print("  SyscallGuard — Attack Simulation")
    print("  Triggering dangerous Tier 1 syscalls for demo...")
    print("=" * 60)
    print()

    attack_memfd_create()
    attack_ptrace()
    attack_shmget()
    attack_personality()
    attack_keyctl()

    print()
    print("  Done. If running under strace, these syscalls are now")
    print("  in the trace log and will be detected by SyscallGuard.")
    print("=" * 60)


if __name__ == "__main__":
    main()
