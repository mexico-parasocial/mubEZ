#!/bin/zsh
# Script to start mubEZ development server with correct Node version

# Load nvm from the correct location
export NVM_DIR="/Users/mlv/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

# Change to project directory
cd "/Users/mlv/Desktop/TH1/mubEZ" || exit 1

# Use Node version from .nvmrc
nvm use

# Start development server
echo "Starting development server with Node $(node --version)..."
pnpm dev
