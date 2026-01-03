# SecOps Remediation Agent

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)
![Security](https://img.shields.io/badge/Security-NIST%20NVD-red?logo=shield)
![AI](https://img.shields.io/badge/AI-RAG%20%2B%20LLM-purple?logo=openai)
![License](https://img.shields.io/badge/License-MIT-green)

> **An automated security assistant that integrates RAG, NIST CVE data, and LLMs to provide actionable vulnerability analysis and remediation scripts.**

## 🎯 Project Overview

The **SecOps Remediation Agent** is designed to bridge the gap between vulnerability detection and remediation. Unlike standard chatbots, this agent focuses on:
- **Real-time Intelligence**: Fetching live CVE data from NIST.
- **Context Awareness**: Using RAG (Retrieval-Augmented Generation) to map vulnerabilities to specific infrastructure context.
- **Actionable Output**: Generating structured JSON data and mitigation scripts for immediate use.

## ✨ Features

- **Real-time CVE Database**: Fetches latest vulnerability data from NIST NVD
- **RAG Pipeline**: Uses FAISS vector store and semantic search for accurate retrieval
- **Dual LLM Support**: 
  - OpenAI GPT-3.5/4 (API-based)
  - Ollama (Free, local LLM)
- **Interactive Web Interface**: Streamlit-based UI
- **Infrastructure Analysis**: Assesses risks based on your system configurations
- **Actionable Recommendations**: Provides specific mitigation strategies

## 🏗️ Architecture

```
User Query → Streamlit UI → Security Chatbot
                               ↓
                           RAG Pipeline
                               ↓
                    ┌──────────┴──────────┐
                    ↓                     ↓
            FAISS Vector Store        LLM (OpenAI/Ollama)
                    ↓                     ↓
            Retrieved Context      Generated Response
                    └──────────┬──────────┘
                               ↓
                        Final Answer
```

## 📚 Documentation

For a deep dive into the system architecture, implementation details, and performance metrics, please refer to the documentation in the `docs/` folder:

* **[Technical Details & Architecture](docs/TECHNICAL_DETAILS.md)**: Detailed breakdown of the RAG pipeline, data preprocessing, and evaluation results.
* **[Architecture Diagram](docs/ARCHITECTURE.md)**: High-level system design.

## 📋 Prerequisites

- Python 3.13.7
- Windows 11
- Internet connection (for CVE data fetching)
- OpenAI API key OR Ollama installation

## 🚀 Installation

### 1. Clone/Download the Project

```bash
# Navigate to your project directory
cd security_chatbot
```

### 2. Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

**Option A: One-Click Install (Recommended)**

```bash
# Windows users
install.bat

# Linux/Mac users
chmod +x install.sh
./install.sh
```

The script will automatically:
1. Check Python version
2. Create virtual environment
3. Install all packages
4. Verify installation

**Option B: Manual Install**

```bash
pip install -r requirements.txt
```

**Note for Python 3.13 users:** If you encounter issues with `faiss-cpu` or `langchain`, the requirements.txt has been updated with compatible versions. If problems persist, see `INSTALLATION_FIX.md` for detailed solutions.

**Verify installation:**
```bash
python test_imports.py
```

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```bash
# Copy the example file
copy .env.example .env
```

Edit `.env` with your settings:

**Option A: Using OpenAI (Recommended)**
```env
OPENAI_API_KEY=sk-your-api-key-here
USE_OLLAMA=false
```

**Option B: Using Ollama (Free, Local)**
```env
USE_OLLAMA=true
OLLAMA_MODEL=llama2
```

### 5. Setup LLM

#### Option A: OpenAI Setup
1. Create account at [OpenAI Platform](https://platform.openai.com/)
2. Generate API key at [API Keys page](https://platform.openai.com/api-keys)
3. Add API key to `.env` file

#### Option B: Ollama Setup (Free Alternative)
1. Download Ollama from [ollama.ai](https://ollama.ai)
2. Install Ollama on Windows
3. Open terminal and run:
```bash
# Download the model (this may take a few minutes)
ollama pull llama2

# Start Ollama server
ollama serve
```
4. Keep the Ollama server running in the background

## 🎮 Usage

### Running the Web Interface

```bash
# Activate virtual environment first (if not already activated)
venv\Scripts\activate

# Run the Streamlit app
streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`

### First-Time Setup in the UI

1. **Configure LLM**: 
   - Choose OpenAI or Ollama in the sidebar
   - Enter API key if using OpenAI
2. **Initialize Chatbot**: Click "🚀 Initialize Chatbot"
3. **Wait for Setup**: The system will:
   - Fetch CVE data from NIST NVD
   - Build vector embeddings
   - Initialize the knowledge base
4. **Start Chatting**: Ask security questions!

### Sample Questions

```
- What are the most critical vulnerabilities in our infrastructure?
- How can we protect against recent Apache vulnerabilities?
- Tell me about CVE-2024-XXXXX and its impact
- What security measures should we implement for our web servers?
- Perform a risk assessment of our Windows servers
- What are the high-severity CVEs from the last month?
```

## 📁 Project Structure

```
security_chatbot/
├── app.py                  # Streamlit web interface
├── chatbot.py             # Main chatbot logic and LLM integration
├── rag_pipeline.py        # RAG implementation with FAISS
├── cve_collector.py       # CVE data collection from NVD API
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
├── .env                  # Your environment configuration (create this)
├── data/                 # CVE data storage (created automatically)
│   └── cve_data.json
└── vector_store/         # FAISS index storage (created automatically)
    ├── faiss_index.bin
    └── documents.pkl
```

## 🔧 Testing

### Test Individual Components

**Test CVE Data Collection:**
```bash
python cve_collector.py
```

**Test RAG Pipeline:**
```bash
python rag_pipeline.py
```

**Test Chatbot:**
```bash
python chatbot.py
```

### Test Scenarios

The system includes sample infrastructure data for testing:
- Web Server Cluster (Ubuntu, Apache, WordPress)
- Database Server (RHEL, PostgreSQL)
- Application Server (Windows Server, .NET, IIS)
- Network Infrastructure (Cisco firewalls, routers)

## 🔄 Updating the Knowledge Base

To fetch latest CVE data:

1. Click "🔄 Update CVE Database" in the sidebar
2. System will fetch CVEs from the last 30 days
3. Knowledge base will be automatically rebuilt
4. Continue chatting with updated information

## ⚠️ Troubleshooting

### Package Installation Issues
If you encounter `faiss-cpu` version errors:
- See `INSTALLATION_FIX.md` for detailed solutions
- Run `python test_imports.py` to verify installation
- Consider using Python 3.11 or 3.12 if Python 3.13 has issues

### "Cannot connect to Ollama"
- Ensure Ollama is installed and running
- Run `ollama serve` in a terminal
- Check if `http://localhost:11434` is accessible

### "OpenAI API Error"
- Verify API key is correct in `.env`
- Check if you have available credits
- Ensure internet connection is stable

### "No CVEs fetched"
- Check internet connection
- NIST NVD API may be temporarily down
- Try again after a few minutes
- Consider adding NVD_API_KEY for higher rate limits

### "Module not found" errors
- Ensure virtual environment is activated
- Run `pip install -r requirements.txt` again
- Verify Python version is 3.13.7

## 📚 External Resources

- [NIST NVD](https://nvd.nist.gov/)
- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Ollama Documentation](https://github.com/ollama/ollama)
- [LangChain Documentation](https://python.langchain.com/)
- [FAISS Documentation](https://github.com/facebookresearch/faiss)
- [Sentence Transformers](https://www.sbert.net/)

## 📝 Customization

### Adding Your Own Infrastructure

Edit `rag_pipeline.py` function `create_sample_infrastructure()`:

```python
{
    'name': 'Your Server Name',
    'type': 'server_type',
    'description': '''
    Your infrastructure description including:
    - Operating System
    - Applications
    - Versions
    - Network exposure
    - Critical assets
    '''
}
```

### Adjusting CVE Fetch Parameters

Edit in `cve_collector.py` or in your code:

```python
cves = collector.fetch_recent_cves(
    days=60,        # Look back 60 days
    max_results=200 # Fetch up to 200 CVEs
)
```

## 🤝 Contributing

This is an academic project. For improvements:
1. Test thoroughly
2. Document changes
3. Maintain code quality
4. Cite any external resources used

## 📄 License

This project is created for educational purposes as part of a university course assignment.

## 👨‍💻 Author

Sunday Chen

## 🙏 Acknowledgments

- NIST National Vulnerability Database for CVE data
- OpenAI for GPT models
- Ollama team for local LLM infrastructure
- HuggingFace for embedding models
- Facebook Research for FAISS
- Streamlit for the web framework

- ## 🤖 AI Assistance Acknowledgment

This project was developed with the assistance of AI tools:

### Code Development
- **Tool**: Claude 4.5 Sonnet (Anthropic)
- **Date**: October 22, 2025
- **Contribution**: Initial codebase generation including RAG pipeline, CVE collector, chatbot interface, and web application
- **Human Modifications**: 
  - Resolved package dependency conflicts (Python 3.13 compatibility)
  - Implemented OpenAI API integration
  - Optimized local LLM performance (Ollama)
  - Added comprehensive error handling and testing suite
  - Created installation automation scripts (`install.bat`, `install.sh`)
  - Extensive debugging and optimization

> **Note**: All AI-generated content was thoroughly reviewed, tested, and significantly modified to meet project requirements and ensure functionality.
