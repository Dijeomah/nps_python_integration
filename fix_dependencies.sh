#!/bin/bash
# fix_dependencies.sh - Fix dependency issues

echo "🔧 Fixing NPS Integration Dependencies"
echo "========================================"
echo ""

# Uninstall problematic packages
echo "📦 Removing old packages..."
pip uninstall -y signxml pyOpenSSL 2>/dev/null

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install core dependencies
echo "📥 Installing core dependencies..."
pip install cryptography==41.0.7
pip install lxml==4.9.3

# Install FastAPI and related
echo "📥 Installing FastAPI..."
pip install fastapi==0.104.1
pip install uvicorn[standard]==0.24.0
pip install pydantic==2.5.0

# Install HTTP client
echo "📥 Installing httpx..."
pip install httpx==0.25.1

# Optional dependencies
echo "📥 Installing optional dependencies..."
pip install python-multipart==0.0.19

echo ""
echo "✅ Dependencies installed successfully!"
echo ""
echo "Note: signxml has been removed. Using direct cryptography implementation."
echo ""
echo "To verify installation, run:"
echo "  python -c 'import fastapi, cryptography, lxml, httpx; print(\"All imports OK\")'"
echo ""