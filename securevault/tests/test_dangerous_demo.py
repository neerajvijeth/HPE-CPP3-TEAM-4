"""
SyscallGuard Demo — Simulated Supply Chain Attack
==================================================
⚠️  THIS FILE LIVES IN syscallguard/demo/ WHERE IT IS SAFE.
    pytest does NOT scan this directory.

To ACTIVATE (trigger SyscallGuard FAIL):
    cp syscallguard/demo/test_dangerous_demo.py securevault/tests/test_dangerous_demo.py
    git add securevault/tests/test_dangerous_demo.py && git commit -m "demo: activate attack" && git push

To DEACTIVATE (restore SyscallGuard PASS):
    rm securevault/tests/test_dangerous_demo.py
    git add -A && git commit -m "demo: deactivate attack" && git push
"""
import os
import subprocess


def test_simulated_reverse_shell():
    """
    Simulates a reverse shell pattern: clone → execve → wait4
    subprocess.run triggers execve (Tier 1 CRITICAL) under strace.
    The sequence analyzer will flag 'clone → execve' patterns.
    """
    result = subprocess.run(
        ["echo", "simulated-exfiltration-payload"],
        capture_output=True, text=True
    )
    assert result.returncode == 0


def test_simulated_data_exfiltration():
    """
    Simulates reading sensitive system files — unusual openat burst.
    The frequency analyzer catches the spike in openat/read calls.
    """
    sensitive_paths = [
        "/etc/hostname",
        "/etc/os-release",
        "/proc/version",
        "/proc/cpuinfo",
        "/proc/meminfo",
    ]
    for path in sensitive_paths:
        try:
            with open(path, 'r') as f:
                _ = f.read()
        except (PermissionError, FileNotFoundError):
            pass


def test_simulated_process_spawn_attack():
    """
    Simulates spawning multiple child processes (fork + execve).
    os.popen triggers fork → execve — flagged as a backdoor pattern.
    """
    commands = ["whoami", "id", "uname -a"]
    for cmd in commands:
        try:
            os.popen(cmd).read()
        except Exception:
            pass
