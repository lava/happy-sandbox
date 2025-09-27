#!/bin/bash

set -e

# Set project name from env; default to current directory name
# This picks up the basename of $PWD if env not provided
PROJECT_NAME=${HAPPY_SANDBOX_PROJECT_NAME:-$(basename "$(pwd)")}

mkdir -p /home/claude/.claude

# Copy combined CLAUDE.md file if it exists
if [ -f /host/claude-md-combined ]; then
    cp /host/claude-md-combined /home/claude/.claude/CLAUDE.md
fi

cat > /home/claude/project-settings.json <<FOO
{
    "projects": {
        "/workspace/$PROJECT_NAME": {
            "allowedTools": [],
            "history": [],
            "mcpContextUris": [],
            "mcpServers": {},
            "enabledMcpjsonServers": [],
            "disabledMcpjsonServers": [],
            "hasTrustDialogAccepted": true,
            "projectOnboardingSeenCount": 1,
            "hasClaudeMdExternalIncludesApproved": false,
            "hasClaudeMdExternalIncludesWarningShown": false,
            "lastTotalWebSearchRequests": 0
        }
    }
}
FOO

# Ensure project directory exists and cd into it
mkdir -p "/workspace/$PROJECT_NAME"
cd "/workspace/$PROJECT_NAME"

cat /host/.claude.json | jq \
    --slurpfile proj /home/claude/project-settings.json \
    '{isQualifiedForDataSharing, hasCompletedOnboarding, oauthAccount, bypassPermissionsModeAccepted: true} + {projects: $proj[0]["projects"]}' \
    > /home/claude/.claude.json
# Copy Claude credentials if they exist
if [ -f /host/claude-credentials.json ]; then
    cp /host/claude-credentials.json /home/claude/.claude/.credentials.json
fi

# Copy Claude credentials to happy home directory if HAPPY_HOME_DIR is set
if [ -n "$HAPPY_HOME_DIR" ] && [ -f /host/claude-credentials.json ]; then
    mkdir -p "$HAPPY_HOME_DIR"
    cp /host/claude-credentials.json "$HAPPY_HOME_DIR/credentials.json"
fi

# Set up Happy client configuration directory if we have credentials
# Use HAPPY_HOME_DIR if set, otherwise fallback to /home/claude/.happy
HAPPY_CONFIG_DIR="${HAPPY_HOME_DIR:-/home/claude/.happy}"

# Determine credentials file source for Happy daemon
CREDENTIALS_SOURCE="${HAPPY_DAEMON_CREDENTIALS_FILE:-/host/happy-credentials.json}"

if [ -f "$CREDENTIALS_SOURCE" ]; then
    # Create happy configuration directory
    mkdir -p "$HAPPY_CONFIG_DIR"

    # Create access.key file with credentials
    cp "$CREDENTIALS_SOURCE" "$HAPPY_CONFIG_DIR/access.key"

    # Extract machine ID from credentials file
    HAPPY_MACHINE_ID=$(cat "$CREDENTIALS_SOURCE" | jq -r '.machine_id // empty')

    # Create settings.json with machine ID
    cat > "$HAPPY_CONFIG_DIR/settings.json" <<EOF
{
  "machineId": "$HAPPY_MACHINE_ID",
  "serverUrl": "https://api.happy.chat",
  "isConfigured": true
}
EOF

    # Set proper permissions for happy configuration files
    chmod 600 "$HAPPY_CONFIG_DIR/access.key"
    chmod 644 "$HAPPY_CONFIG_DIR/settings.json"
    chown claude:claude "$HAPPY_CONFIG_DIR/access.key" "$HAPPY_CONFIG_DIR/settings.json"

    if [ -n "$HAPPY_MACHINE_ID" ]; then
        echo "Happy client configuration set up with machine ID: $HAPPY_MACHINE_ID"
    else
        echo "Happy client configuration set up, but no machine ID found in credentials"
    fi
fi

# Source NVM to get Node.js and npm packages in PATH
export NVM_DIR="/home/claude/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

exec "$@"
