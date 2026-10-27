#!/usr/bin/env bash
# Developer Workstation Setup Script (for subsidiary developers on Linux/macOS)
# Configures Git URL rewriting, SSH host aliases, and dual-remote monitoring.
set -euo pipefail

TARGET_REPO_DIR="${1:-.}"
SERVER_IP="10.42.0.252"

echo "=== Configuring Developer Workstation Client ==="

# 1. Global Git URL rewriting:
# Replaces 'smart_repo:smart/smart_encrypted.git' in memory with 'git@10.42.0.252:smart/smart.git'
git config --global url."git@smart_repo:smart/smart.git".insteadOf "git@smart_repo:smart/smart_encrypted.git"
echo "[+] Configured global Git insteadOf rule."

# 2. Local repository Remote URL camouflage:
if [ -d "$TARGET_REPO_DIR/.git" ]; then
    git -C "$TARGET_REPO_DIR" remote set-url origin git@smart_repo:smart/smart_encrypted.git
    echo "[+] Set origin remote URL in $TARGET_REPO_DIR to git@smart_repo:smart/smart_encrypted.git"

    # Add optional read-only remote for inspecting HQ view
    if ! git -C "$TARGET_REPO_DIR" remote | grep -q "origin-hq"; then
        git -C "$TARGET_REPO_DIR" remote add origin-hq "git@$SERVER_IP:smart/smart_encrypted.git" || true
        git -C "$TARGET_REPO_DIR" config remote.origin-hq.pushurl "FORBIDDEN_DO_NOT_PUSH" || true
        echo "[+] Added read-only 'origin-hq' remote for inspecting published commits."
    fi
fi

# 3. SSH Configuration guidance:
SSH_CONFIG="$HOME/.ssh/config"
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

if ! grep -q "Host smart_repo" "$SSH_CONFIG" 2>/dev/null; then
    cat <<EOF >> "$SSH_CONFIG"

# Subsidiary Developer Git Host Alias
Host smart_repo
    HostName $SERVER_IP
    User git
    Port 22
    IdentityFile ~/.ssh/id_rsa
EOF
    chmod 600 "$SSH_CONFIG"
    echo "[+] Added 'smart_repo' Host configuration to $SSH_CONFIG"
else
    echo "[*] 'smart_repo' Host already exists in $SSH_CONFIG"
fi

echo "=== Developer Client Configuration Completed Successfully! ==="
