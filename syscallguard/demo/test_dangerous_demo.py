"""
SyscallGuard Demo — Simulated Supply Chain Attack
==================================================
⚠️  THIS FILE LIVES IN syscallguard/demo/ WHERE IT IS SAFE.
    pytest does NOT scan this directory.

To ACTIVATE (trigger SyscallGuard FAIL):
    cp syscallguard/demo/test_dangerous_demo.py securevault/tests/test_dangerous_demo.py
    git add . && git commit -m "demo: activate attack simulation" && git push

To DEACTIVATE (restore SyscallGuard PASS):
    rm securevault/tests/test_dangerous_demo.py
    git add -A && git commit -m "demo: deactivate attack" && git push

WHY THESE SPECIFIC SYSCALLS:
    Normal pytest already uses clone, execve, socket, etc.
    To trigger a FAIL, we need syscalls ABSENT from the baseline.
    These tests trigger: memfd_create, shmget, shmat, ptrace, personality
    — all Tier 1 CRITICAL syscalls that no normal app would use.
"""
import ctypes
import ctypes.util
import os
import struct


def _get_libc():
    """Get a handle to libc for direct syscall invocation."""
    libc_name = ctypes.util.find_library('c')
    if libc_name:
        return ctypes.CDLL(libc_name, use_errno=True)
    return ctypes.CDLL("libc.so.6", use_errno=True)


def test_memfd_create_fileless_payload():
    """
    ATTACK SIMULATION: Fileless malware execution vector.

    memfd_create() creates an anonymous file in memory — attackers use this
    to write and execute malicious payloads without touching the filesystem.

    This triggers the 'memfd_create' syscall (Tier 1 CRITICAL, weight +10).
    Even strace capturing the attempt is enough for SyscallGuard detection.
    """
    try:
        # Python 3.8+ has os.memfd_create()
        fd = os.memfd_create("suspicious_payload")
        os.write(fd, b"simulated malware binary content")
        os.close(fd)
    except (OSError, AttributeError):
        # If memfd_create unavailable, try via syscall number (319 on x86_64)
        try:
            libc = _get_libc()
            libc.syscall(319, b"payload", 0)
        except Exception:
            pass
    # Test always passes — we just need strace to capture the syscall
    assert True


def test_ptrace_process_injection():
    """
    ATTACK SIMULATION: Process injection / debugging vector.

    ptrace() allows attaching to another process to read/write its memory.
    Attackers use this for code injection and credential theft.

    This triggers the 'ptrace' syscall (Tier 1 CRITICAL, weight +10).
    The call will FAIL (EPERM) but strace still captures it.
    """
    try:
        libc = _get_libc()
        # PTRACE_TRACEME = 0 — attempt to trace self (harmless, but logged)
        libc.ptrace(0, 0, 0, 0)
    except Exception:
        pass
    assert True


def test_shmget_shared_memory_attack():
    """
    ATTACK SIMULATION: Shared memory manipulation for IPC-based exfiltration.

    shmget/shmat allow creating shared memory segments — attackers use these
    for inter-process communication to exfiltrate data or inject code.

    This triggers 'shmget' and 'shmat' syscalls (Tier 1 CRITICAL, weight +10 each).
    """
    try:
        libc = _get_libc()
        # IPC_PRIVATE=0, size=4096, flags=IPC_CREAT|0o666 = 0o1666 = 950
        shmid = libc.shmget(0, 4096, 0o1666)
        if shmid >= 0:
            # Attach, write, detach, remove
            libc.shmat.restype = ctypes.c_void_p
            addr = libc.shmat(shmid, 0, 0)
            if addr and addr != ctypes.c_void_p(-1).value:
                libc.shmdt(addr)
            # IPC_RMID = 0
            libc.shmctl(shmid, 0, 0)
    except Exception:
        pass
    assert True


def test_personality_syscall():
    """
    ATTACK SIMULATION: Process personality manipulation.

    personality() changes the process execution domain — used in exploit
    chains to disable ASLR (Address Space Layout Randomization) before
    launching an attack.

    This triggers the 'personality' syscall (Tier 1 CRITICAL, weight +10).
    """
    try:
        libc = _get_libc()
        # Read current personality (passing 0xffffffff just reads, no change)
        current = libc.personality(0xffffffff)
        # This is a read-only call, completely safe
    except Exception:
        pass
    assert True


def test_keyctl_credential_access():
    """
    ATTACK SIMULATION: Kernel keyring access for credential theft.

    keyctl() accesses the kernel key management facility — attackers use
    this to steal stored credentials and authentication tokens.

    This triggers the 'keyctl' syscall (Tier 1 CRITICAL, weight +10).
    """
    try:
        libc = _get_libc()
        # KEYCTL_GET_KEYRING_ID = 0, KEY_SPEC_SESSION_KEYRING = -3
        libc.syscall(250, 0, -3, 0)  # keyctl syscall number on x86_64
    except Exception:
        pass
    assert True
