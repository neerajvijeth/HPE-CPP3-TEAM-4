# SyscallGuard: eBPF-Derived Syscall Behavioral Fingerprinting

> A first-class supply chain attack detector for CI/CD pipelines.

## 🎯 What Is This?

SyscallGuard treats **syscall profile deltas** as a cryptographic behavioral fingerprint. If your dependency `requests==2.28` generates a profile of 42 syscalls and `requests==2.29` suddenly adds `ptrace`, `process_vm_readv`, or `socket` — that is a **behavioral anomaly** that no CVE database would catch in time.

This is the core novelty: **behavioral detection** instead of **signature-based detection**.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CI/CD Pipeline (GitHub Actions)                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │  pytest + ig  │──▶│  Profile Registry │──▶│ Jaccard Diff     │  │
│  │  (strace)     │    │  (GH Artifacts)   │    │ Engine           │  │
│  └──────────────┘    └──────────────────┘    └───────┬──────────┘  │
│         │                                            │              │
│         ▼                                            ▼              │
│  ┌──────────────┐                           ┌──────────────────┐   │
│  │  Dependency   │                           │  Risk Score +    │   │
│  │  Exerciser    │                           │  Blast Radius    │   │
│  │  (strace)     │                           │  Containment %   │   │
│  └──────────────┘                           └──────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 📁 File Structure

```
syscallguard/
├── README.md                  # This file
├── syscall_taxonomy.json      # Hand-curated danger tier map (100+ syscalls)
├── generate_profile.py        # strace → JSON profile converter
├── profile_diff.py            # Jaccard similarity diff engine + risk scoring
├── dep_exerciser.py           # Dependency-isolated profiler
├── blast_radius.py            # Blast radius containment calculator
├── store_profile.sh           # Profile versioning helper
└── tests/
    ├── test_profile_diff.py   # Unit tests for diff engine
    ├── test_blast_radius.py   # Unit tests for blast radius
    ├── test_generate_profile.py # Unit tests for profile generator
    └── sample_profiles/       # Test fixtures
        ├── baseline.json          # Known-good profile (42 syscalls)
        ├── current_with_drift.json # Simulated attack (+ptrace, +execve)
        └── current_benign_update.json # Legit update (+getrandom, +statx)
```

## 🔬 Core Components

### 1. Syscall Taxonomy (`syscall_taxonomy.json`)
Hand-curated classification of ~100 Linux syscalls into three danger tiers:

| Tier | Risk Level | Weight | Examples |
|------|-----------|--------|----------|
| Tier 1 | 🔴 CRITICAL | ×10 | `execve`, `ptrace`, `socket`, `mount`, `setuid` |
| Tier 2 | 🟡 SUSPICIOUS | ×3 | `openat`, `unlink`, `chmod`, `pipe`, `ioctl` |
| Tier 3 | 🟢 BENIGN | ×1 | `read`, `write`, `mmap`, `brk`, `getpid` |

### 2. Jaccard Diff Engine (`profile_diff.py`)
Computes **Jaccard similarity** between current and baseline profiles (presence/absence of syscalls) and classifies novel syscalls by danger tier.

### 3. Frequency Anomaly Analyzer (`frequency_analyzer.py`)
Detects frequency-based anomalies that Jaccard analysis misses. If a dependency starts abusing an existing syscall (e.g., calling `socket` 10,000x more frequently to exfiltrate data), this module catches the spike.

### 4. Cosine Similarity Engine (`cosine_engine.py`)
Computes cosine similarity on frequency vectors to detect magnitude-based structural shifts in behavior, complementing Jaccard's set-based approach.

### 5. Sequence (N-gram) Analyzer (`sequence_analyzer.py`)
Extracts 2-grams and 3-grams from raw `strace` logs to detect malicious sequences of otherwise benign syscalls (e.g., `socket → connect → execve` for a reverse shell).

### 6. Cross-Profile Correlator (`cross_correlator.py`)
Compares the application's test suite profile against dependency profiles to reveal **untested attack surface**—syscalls made by dependencies that the tests never exercise.

### 7. Blast Radius Containment (`blast_radius.py`)
Measures what percentage of known exploit technique syscalls are blocked by your app's profile across 10 categories (RCE, privilege escalation, etc.).

### 8. Dependency Exerciser (`dep_exerciser.py`)
Imports and exercises each dependency to attribute syscall drift to specific packages—answering **which** dependency introduced the anomaly.

### 9. Seccomp Profile Generator (`seccomp_generator.py`)
Turns detection into **prevention** by auto-generating an OCI-compliant JSON seccomp profile from the baseline. This configures the Linux kernel to physically block any syscall not in the whitelist during runtime.

## 📊 Interpreting Results

### Jaccard Similarity
- `≥ 95%` 🟢 **STABLE** — Profile matches baseline closely
- `80-95%` 🟡 **MINOR DRIFT** — Some changes, review recommended
- `< 80%` 🔴 **SIGNIFICANT DRIFT** — Major behavioral change detected

### Risk Score Threshold
Default threshold: **10** (equivalent to 1 tier-1 syscall like `ptrace`)

| Score | Meaning |
|-------|---------|
| 0 | No novel syscalls — identical profile |
| 1-9 | Minor benign additions only |
| 10+ | 🚨 At least one critical syscall introduced |

### Blast Radius Containment
- `≥ 85%` 🟢 **EXCELLENT** — Most exploit vectors blocked
- `60-85%` 🟡 **MODERATE** — Some exposure to exploit techniques
- `< 60%` 🔴 **LOW** — Significant exploit surface

## 🧪 Running Locally

```bash
# Run unit tests
cd syscallguard && python -m pytest tests/ -v

# Compare sample profiles (simulated attack)
python profile_diff.py \
  tests/sample_profiles/current_with_drift.json \
  tests/sample_profiles/baseline.json

# Compare sample profiles (benign update)
python profile_diff.py \
  tests/sample_profiles/current_benign_update.json \
  tests/sample_profiles/baseline.json

# Compute blast radius
python blast_radius.py tests/sample_profiles/baseline.json
```

## 🆚 Comparison with Existing Tools

| Feature | SBOM/CVE Feeds | Trivy/Grype | SyscallGuard |
|---------|---------------|-------------|-------------|
| Detection type | Signature | Signature | Behavioral |
| Zero-day detection | ❌ | ❌ | ✅ |
| Supply chain focus | Partial | Partial | Primary |
| Runtime behavior | ❌ | ❌ | ✅ |
| Dependency attribution | ❌ | ❌ | ✅ |
| Blast radius metric | ❌ | ❌ | ✅ |
| Cost | Free | Free | Free |

## 📚 Research Context

This tool implements the thesis from:

> **SyscallGuard: eBPF-Derived Syscall Behavioral Fingerprinting as a First-Class Supply Chain Attack Detector in CI/CD Pipelines**

The key insight: current tools detect known threats (CVEs, signatures). SyscallGuard detects **unknown threats** by identifying when software starts doing things it has never done before at the kernel level.
