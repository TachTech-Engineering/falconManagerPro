#!/bin/bash
# Quick setup script for FalconPy project

set -e

PROJECT_DIR="$HOME/Development/Project/falconpy"
cd "$PROJECT_DIR"

echo "====================================="
echo "FalconPy Project Setup"
echo "====================================="
echo

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "[1/4] Creating Python virtual environment..."
    python -m venv venv
else
    echo "[1/4] Virtual environment already exists, skipping..."
fi

echo "[2/4] Activating virtual environment..."
source venv/bin/activate

echo "[3/4] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[4/4] Checking for .env file..."
if [ ! -f ".env" ]; then
    echo "Creating .env from template..."
    cp .env.example .env
    echo
    echo "⚠️  IMPORTANT: Edit .env and add your CrowdStrike API credentials"
    echo "   File location: $PROJECT_DIR/.env"
else
    echo ".env file already exists"
fi

echo
echo "====================================="
echo "Setup Complete!"
echo "====================================="
echo
echo "Next steps:"
echo "1. Edit .env with your CrowdStrike credentials:"
echo "   nano .env"
echo
echo "2. Activate virtual environment:"
echo "   source venv/bin/activate"
echo
echo "3. Test connection:"
echo "   python scripts/query_detections.py --test-connection"
echo
echo "4. Run your first query:"
echo "   python scripts/query_detections.py --filter 'status:\"new\"' --limit 10"
echo
