#!/bin/bash
# Railway deployment script
echo "🚂 Preparing Railway deployment..."

# Backup current package.json
cp package.json package.vercel.json

# Switch to Railway package.json
cp package.railway.json package.json

echo "✅ Switched to Railway configuration"
echo "📦 Package name: $(cat package.json | grep '"name"' | head -1)"
echo "🚀 Starting Railway deployment..."