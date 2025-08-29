#!/bin/bash

set -e

# Set project name from env; default to current directory name
# This picks up the basename of $PWD if env not provided
PROJECT_NAME=${HAPPY_SANDBOX_PROJECT_NAME:-$(basename "$(pwd)")}

mkdir -p /home/claude/.claude

cat > /home/claude/project.json <<FOO
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
    --slurpfile proj /home/claude/project.json \
    '{isQualifiedForDataSharing, hasCompletedOnboarding, oauthAccount} + {projects: $proj[0]["projects"]}' \
    > /home/claude/.claude.json
cp /host/.credentials.json /home/claude/.claude/.credentials.json

# Source NVM to get Node.js and npm packages in PATH
export NVM_DIR="/home/claude/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

exec "$@"
