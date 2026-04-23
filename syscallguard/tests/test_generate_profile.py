#!/usr/bin/env python3
"""
Unit tests for SyscallGuard — generate_profile.py
Tests the strace log parser and profile generator.
"""

import json
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generate_profile import parse_strace_log, generate_profile, compute_requirements_hash


@pytest.fixture
def sample_strace_log(tmp_path):
    """Create a temporary sample strace log file"""
    content = """12345      0.000001 execve("/usr/bin/python3", ["python3", "-m", "pytest"], 0x7fff...) = 0
12345      0.000050 brk(NULL)           = 0x55c123456000
12345      0.000100 arch_prctl(0x3001, 0x7fff9b2c3e00) = -1 EINVAL (Invalid argument)
12345      0.000120 mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f...
12345      0.000150 access("/etc/ld.so.preload", R_OK) = -1 ENOENT
12345      0.000200 openat(AT_FDCWD, "/usr/lib/python3/lib-dynload", O_RDONLY|O_CLOEXEC) = 3
12345      0.000250 close(3)            = 0
12345      0.000300 read(3, "\\177ELF\\2\\1\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0>\\0\\1\\0\\0\\0\\0\\0\\0\\0"..., 832) = 832
12345      0.000350 write(1, "test output\\n", 12) = 12
12345      0.000400 fstat(3, {st_mode=S_IFREG|0644, st_size=12345, ...}) = 0
12345      0.000450 mprotect(0x7f..., 4096, PROT_READ) = 0
12345      0.000500 munmap(0x7f..., 8192) = 0
12345      0.000550 getpid()            = 12345
12345      0.000600 futex(0x7f..., FUTEX_WAKE_PRIVATE, 1) = 0
12346      0.000650 clone(child_stack=0x7f..., flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND) = 12347
12346      0.000700 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
12346      0.000750 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
12346      0.000800 sendto(4, "GET / HTTP/1.1\\r\\n", 17, 0, NULL, 0) = 17
12346      0.000850 recvfrom(4, "HTTP/1.1 200 OK\\r\\n", 8192, 0, NULL, NULL) = 19
12345      0.001000 rt_sigaction(SIGCHLD, {sa_handler=SIG_DFL}, NULL, 8) = 0
12345      0.001050 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
12345      0.001100 exit_group(0)       = ?
12345      0.001100 +++ exited with 0 +++
"""
    log_path = tmp_path / "test_strace.log"
    log_path.write_text(content)
    return str(log_path)


@pytest.fixture
def sample_strace_with_resumed(tmp_path):
    """Create strace log with split/resumed syscalls"""
    content = """12345 openat(AT_FDCWD, "/some/file" <unfinished ...>
12346 read(3, "data", 4096)            = 45
12345 <... openat resumed>)            = 5
12345 read(5, "content", 4096)         = 100
12345 close(5)                         = 0
"""
    log_path = tmp_path / "test_resumed.log"
    log_path.write_text(content)
    return str(log_path)


class TestStraceParser:

    def test_parse_basic_log(self, sample_strace_log):
        """Should extract all unique syscalls from strace log"""
        syscalls, counts = parse_strace_log(sample_strace_log)
        assert "read" in syscalls
        assert "write" in syscalls
        assert "openat" in syscalls
        assert "close" in syscalls
        assert "socket" in syscalls
        assert "connect" in syscalls
        assert "execve" in syscalls

    def test_parse_counts(self, sample_strace_log):
        """Should count syscall frequencies"""
        syscalls, counts = parse_strace_log(sample_strace_log)
        assert counts["read"] >= 1
        assert counts["write"] >= 1

    def test_parse_excludes_noise(self, sample_strace_log):
        """Should not include strace noise like '+++' lines"""
        syscalls, counts = parse_strace_log(sample_strace_log)
        assert "+++" not in syscalls
        assert "---" not in syscalls

    def test_parse_resumed_lines(self, sample_strace_with_resumed):
        """Should handle split/resumed syscall lines"""
        syscalls, counts = parse_strace_log(sample_strace_with_resumed)
        assert "openat" in syscalls
        assert counts["openat"] >= 1

    def test_parse_empty_file(self, tmp_path):
        """Empty strace log should return empty results"""
        log_path = tmp_path / "empty.log"
        log_path.write_text("")
        syscalls, counts = parse_strace_log(str(log_path))
        assert len(syscalls) == 0
        assert len(counts) == 0


class TestProfileGenerator:

    def test_generate_profile_structure(self, sample_strace_log, tmp_path):
        """Generated profile should have correct structure"""
        output = str(tmp_path / "profile.json")
        profile = generate_profile(sample_strace_log, output, source="pytest", git_sha="abc123")

        assert profile["version"] == "1.0"
        assert profile["generator"] == "syscallguard"
        assert profile["source"] == "pytest"
        assert profile["app_version"] == "abc123"
        assert isinstance(profile["syscalls"], list)
        assert isinstance(profile["syscall_counts"], dict)
        assert profile["total_unique_syscalls"] > 0

    def test_generate_profile_writes_file(self, sample_strace_log, tmp_path):
        """Should write valid JSON to output file"""
        output = str(tmp_path / "profile.json")
        generate_profile(sample_strace_log, output)

        with open(output) as f:
            data = json.load(f)
        assert "syscalls" in data

    def test_requirements_hash(self, tmp_path):
        """Should compute consistent SHA256 hash"""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==2.3.3\nrequests==2.31.0\n")

        hash1 = compute_requirements_hash(str(req_file))
        hash2 = compute_requirements_hash(str(req_file))
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex digest length

    def test_requirements_hash_missing_file(self):
        """Should return sentinel value for missing file"""
        result = compute_requirements_hash("/nonexistent/file.txt")
        assert result == "file_not_found"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
