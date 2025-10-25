#!/bin/bash

echo "🎨 Starting AntiV-AI Frontend Dashboard..."
echo "📍 Dashboard will be available at: http://localhost:3000"
echo "⚡ Hot reload enabled for development"
echo ""

# Navigate to frontend directory
cd "$(dirname "$0")/frontend"

# Start the React development server
npm start
