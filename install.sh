#!/bin/bash
# Security Chatbot - One-Click Installation Script for Linux/Mac
# This script automates the installation process

echo "==============================================================="
echo "  Security Chatbot - Automated Installation"
echo "==============================================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed or not in PATH"
    echo "Please install Python 3.11 or higher"
    exit 1
fi

echo "[1/6] Python found:"
python3 --version
echo ""

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "[2/6] Virtual environment already exists. Skipping creation."
else
    echo "[2/6] Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment"
        exit 1
    fi
    echo "Virtual environment created successfully."
fi
echo ""

# Activate virtual environment
echo "[3/6] Activating virtual environment..."
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to activate virtual environment"
    exit 1
fi
echo ""

# Upgrade pip
echo "[4/6] Upgrading pip..."
python -m pip install --upgrade pip --quiet
echo "pip upgraded."
echo ""

# Install packages
echo "[5/6] Installing required packages..."
echo "This may take 5-10 minutes. Please be patient..."
echo ""

pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo ""
    echo "[WARNING] Some packages may have failed to install."
    echo "Trying individual installation..."
    echo ""
    
    pip install faiss-cpu
    pip install streamlit
    pip install langchain langchain-community langchain-openai
    pip install langchain-text-splitters langchain-core
    pip install sentence-transformers
    pip install openai
    pip install requests python-dotenv pandas numpy tiktoken
fi
echo ""

# Verify installation
echo "[6/6] Verifying installation..."
python test_imports.py

if [ $? -ne 0 ]; then
    echo ""
    echo "[WARNING] Some packages may not be installed correctly."
    echo "Please check the output above and refer to INSTALLATION_FIX.md"
else
    echo ""
    echo "==============================================================="
    echo "  Installation Complete!"
    echo "==============================================================="
    echo ""
    echo "Next steps:"
    echo "  1. Configure .env file (copy from .env.example)"
    echo "  2. Run: streamlit run app.py"
    echo ""
fi
