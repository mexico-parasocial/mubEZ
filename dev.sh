#!/bin/zsh
# Script to start mubEZ development server with correct Node version

# Load nvm from the correct location
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

# Always run from the directory this script lives in
cd "$(dirname "$0")" || exit 1

# Use the Node major this repo's engines field requires
nvm use 24

# Start development server
echo "Starting development server with Node $(node --version)..."
pnpm dev
