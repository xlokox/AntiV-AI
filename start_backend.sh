#!/bin/bash

echo "🚀 Starting AntiV-AI Backend Server..."
echo "📍 Server will be available at: http://localhost:8000"
echo "📊 API Documentation: http://localhost:8000/docs"
echo ""

# Navigate to project directory
cd "$(dirname "$0")"

# Start the FastAPI server
uvicorn src.app:app --host 127.0.0.1 --port 8000 --reload
