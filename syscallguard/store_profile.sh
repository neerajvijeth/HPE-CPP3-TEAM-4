#!/bin/bash
# SyscallGuard — Profile Versioning Helper
# Prepares the syscall profile for versioned storage as a GitHub artifact.
#
# Usage: ./store_profile.sh <profile.json> <requirements.txt> <output_dir>

set -euo pipefail

PROFILE_JSON="${1:?Usage: store_profile.sh <profile.json> <requirements.txt> <output_dir>}"
REQ_FILE="${2:?Usage: store_profile.sh <profile.json> <requirements.txt> <output_dir>}"
OUTPUT_DIR="${3:?Usage: store_profile.sh <profile.json> <requirements.txt> <output_dir>}"

# Compute version keys
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
REQ_HASH=$(sha256sum "$REQ_FILE" | cut -c1-12)
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Copy profile with versioned filename
VERSIONED_NAME="syscall-profile-${GIT_SHA}-${REQ_HASH}-${TIMESTAMP}.json"
cp "$PROFILE_JSON" "${OUTPUT_DIR}/${VERSIONED_NAME}"

# Also copy as "latest" for easy baseline retrieval
cp "$PROFILE_JSON" "${OUTPUT_DIR}/pytest-profile.json"

echo "✅ Profile stored:"
echo "   Versioned: ${OUTPUT_DIR}/${VERSIONED_NAME}"
echo "   Latest:    ${OUTPUT_DIR}/pytest-profile.json"
echo "   Git SHA:   ${GIT_SHA}"
echo "   Req Hash:  ${REQ_HASH}"
