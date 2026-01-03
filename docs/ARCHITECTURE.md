# SecOps Remediation Agent - System Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          USER INTERFACE                         │
│                       (Streamlit Web App)                       │
│  - Vulnerability Dashboard                                      │
│  - Chat / Remediation Interface                                 │
│  - Configuration Panel                                          │
│  - Knowledge Base Management                                    │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     SECOPS AGENT ENGINE                         │
│                        (chatbot.py)                             │
│  - Query Processing & Intent Recognition                        │
│  - Context Integration                                          │
│  - Remediation Logic                                            │
│  - Structured Output Parsing (JSON)                             │
└──────────────┬────────────────────────────┬─────────────────────┘
               │                            │
               ▼                            ▼
┌──────────────────────────┐    ┌──────────────────────────┐
│      RAG PIPELINE        │    │     LLM INTERFACE        │
│    (rag_pipeline.py)     │    │     (chatbot.py)         │
│                          │    │                          │
│  - Text Chunking         │    │  Strategy Pattern:       │
│  - Embedding Generation  │    │  1. OpenAI (Cloud)       │
│  - Vector Indexing       │    │  2. Ollama (Local)       │
│  - Similarity Search     │    │                          │
└───────────┬──────────────┘    └──────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        KNOWLEDGE BASE                           │
│                                                                 │
│  ┌─────────────────────┐        ┌─────────────────────┐         │
│  │    VECTOR STORE     │        │    CVE DATABASE     │         │
│  │    (FAISS Index)    │        │   (cve_collector.py)│         │
│  │                     │        │                     │         │
│  │  - Document Chunks  │        │  - CVE Records      │         │
│  │  - Embeddings       │        │  - CVSS Scores      │         │
│  │  - Metadata         │        │  - Descriptions     │         │
│  └─────────────────────┘        │  - Affected Products│         │
│                                 └─────────┬───────────┘         │
│                                           │                     │
│  ┌─────────────────────┐                  │                     │
│  │  INFRASTRUCTURE DB  │                  │                     │
│  │    (Sample Data)    │                  │                     │
│  │                     │◄─────────────────┘                     │
│  │  - Server Configs   │                                        │
│  │  - OS Versions      │                                        │
│  │  - Services         │                                        │
│  │  - Network Info     │                                        │
│  └─────────────────────┘                                        │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     EXTERNAL DATA SOURCES                       │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │          NIST National Vulnerability Database            │   │
│  │               [https://nvd.nist.gov/](https://nvd.nist.gov/)                      │   │
│  │  - CVE Records                                           │   │
│  │  - Real-time Updates                                     │   │
│  │  - RESTful API                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagram

```
┌────────────┐
│    User    │
│    Query   │
└─────┬──────┘
      │
      ▼
┌─────────────────────────────────────┐
│  1. Query Embedding                 │
│     (sentence-transformers)         │
│     "Patch for Apache CVE?"         │
│            ↓                        │
│     [0.23, 0.45, 0.12, ...]         │
└─────────────┬───────────────────────┘
      │
      ▼
┌─────────────────────────────────────┐
│  2. Vector Search (FAISS)           │
│     - L2 Distance Calculation       │
│     - Top-K Retrieval (k=5)         │
│            ↓                        │
│     Retrieved Documents:            │
│     Doc1: CVE-2024-1234 (Score:0.9) │
│     Doc2: Apache Config (Score:0.8) │
└─────────────┬───────────────────────┘
      │
      ▼
┌─────────────────────────────────────┐
│  3. Context Assembly                │
│     Combine:                        │
│     - User Query                    │
│     - Retrieved Documents           │
│     - System Instructions (JSON)    │
│            ↓                        │
│     Complete Prompt                 │
└─────────────┬───────────────────────┘
      │
      ▼
┌─────────────────────────────────────┐
│  4. LLM Generation                  │
│     (OpenAI GPT-3.5 / Ollama)       │
│     - Process Context               │
│     - Generate Remediation Plan     │
│     - Format as JSON Object         │
└─────────────┬───────────────────────┘
      │
      ▼
┌─────────────────────────────────────┐
│  5. Structured Output Parsing       │
│     - Extract JSON Data             │
│     - Generate Patch Script         │
│     - Format Severity Metrics       │
└─────────────┬───────────────────────┘
      │
      ▼
┌────────────────┐
│  Display to    │
│  User (UI)     │
└────────────────┘
```

## Component Interaction

```
app.py (Streamlit UI)
    │
    ├─→ Initialize System
    │   └─→ chatbot.py::create_chatbot()
    │       ├─→ cve_collector.py::fetch_recent_cves()
    │       │   └─→ NIST NVD API
    │       ├─→ rag_pipeline.py::build_knowledge_base()
    │       │   ├─→ SentenceTransformer (embeddings)
    │       │   └─→ FAISS (indexing)
    │       └─→ LLMInterface (OpenAI/Ollama)
    │
    ├─→ Process User Query
    │   └─→ chatbot.py::SecOpsAgent.chat()
    │       ├─→ rag_pipeline.py::retrieve()
    │       │   └─→ FAISS similarity search
    │       └─→ LLMInterface::generate_response()
    │           └─→ OpenAI API / Ollama
    │
    └─→ Display Remediation
        ├─→ Natural Language Response
        ├─→ Structured Data Table (JSON)
        └─→ Executable Patch Script
```

## File Dependencies

```
app.py
  │
  ├── imports chatbot.py
  │      │
  │      ├── imports rag_pipeline.py
  │      │      │
  │      │      ├── imports sentence_transformers
  │      │      ├── imports faiss
  │      │      └── imports langchain
  │      │
  │      ├── imports cve_collector.py
  │      │      │
  │      │      └── imports requests
  │      │
  │      └── imports openai / ollama
  │
  └── imports streamlit
```

## Data Storage Structure

```
secops-remediation-agent/
├── data/                           # CVE data storage
│   └── cve_data.json               # Fetched CVE records
│
├── vector_store/                   # FAISS index storage
│   ├── faiss_index.bin             # Vector index
│   └── documents.pkl               # Document metadata
│
└── .env                            # Configuration
    ├── OPENAI_API_KEY
    ├── USE_OLLAMA
    └── NVD_API_KEY (optional)
```

## RAG Pipeline Detail

```
Input Document
      │
      ▼
┌─────────────────────┐
│  Text Splitting     │
│  (RecursiveText     │
│   Splitter)         │
│  - Chunk: 800 chars │
│  - Overlap: 100     │
└──────┬──────────────┘
      │
      ▼
┌─────────────────────┐
│  Embedding          │
│  Generation         │
│  (all-MiniLM-L6-v2) │
│  Output: 384-dim    │
│  vector             │
└──────┬──────────────┘
      │
      ▼
┌─────────────────────┐
│  FAISS Indexing     │
│  (IndexFlatL2)      │
│  - L2 distance      │
│  - Fast search      │
└──────┬──────────────┘
      │
      ▼
   Vector Store
   (Persistent)
```

## Query Processing Flow (Example)

```
User Query: "Fix Apache vulnerability CVE-2024-1234"
      │
      ▼
[Embedding] → [0.12, 0.34, 0.56, ..., 0.78]
      │
      ▼
[FAISS Search] → Top 5 Similar Vectors
      │
      ├─→ Doc1: "CVE-2024-1234 details & fix" (score: 0.92)
      └─→ Doc2: "Apache 2.4 configuration" (score: 0.85)
      │
      ▼
[Context Assembly]
      │
      ├─→ System Prompt: "You are a SecOps Agent. Output JSON."
      ├─→ Context Docs: [Doc1, Doc2]
      └─→ User Query: "Fix Apache..."
      │
      ▼
[LLM Processing]
      │
      ▼
[Response Generation]
"Based on the analysis, here is the remediation plan:"

```json
{
  "cve_id": "CVE-2024-1234",
  "severity": "CRITICAL",
  "affected_component": "Apache HTTP Server 2.4.x",
  "mitigation_command": "sudo apt-get update && sudo apt-get install --only-upgrade apache2"
}
```

## Testing Architecture

```
test_chatbot.py
      │
      ├─→ Test 1: CVE Collection
      │   └─→ cve_collector.py
      │       └─→ NIST NVD API
      │
      ├─→ Test 2: RAG Pipeline
      │   └─→ rag_pipeline.py
      │       ├─→ Build knowledge base
      │       ├─→ Test retrieval
      │       └─→ Save/load index
      │
      ├─→ Test 3: LLM Integration
      │   └─→ chatbot.py::LLMInterface
      │       ├─→ OpenAI test
      │       └─→ Ollama test
      │
      ├─→ Test 4: Agent Logic
      │   └─→ chatbot.py::SecOpsAgent
      │       ├─→ End-to-end query
      │       └─→ JSON output validation
      │
      └─→ Test 5: Evaluation Metrics
          └─→ Calculate precision/recall
```

## Technology Stack Layers

The system is built on a modern AI engineering stack, separated into logical layers to ensure modularity and maintainability.

```mermaid
graph TD
    subgraph Presentation ["💻 Presentation Layer"]
        UI[Streamlit Web Interface]
        Config[Configuration Panel]
    end

    subgraph Application ["⚙️ Application Layer"]
        Logic[Agent Core Logic]
        RAG[RAG Pipeline Controller]
        Collector[CVE Data Collector]
    end

    subgraph Framework ["🛠️ Framework Layer"]
        LC[LangChain]
        ST[Sentence-Transformers]
        Req[Requests / Pandas]
    end

    subgraph Model ["🧠 Model Layer"]
        LLM[LLM Engine<br/>(OpenAI / Ollama)]
        Embed[Embedding Model<br/>(all-MiniLM-L6-v2)]
    end

    subgraph Data ["💾 Data Layer"]
        VecDB[(FAISS Vector Store)]
        NVD[(NIST CVE Database)]
        Env[Environment Variables]
    end

    Presentation --> Application
    Application --> Framework
    Framework --> Model
    Model --> Data
```

### Stack Details

| Layer | Component | Purpose |
| :--- | :--- | :--- |
| **Presentation** | **Streamlit** | Provides the interactive web UI, chat history display, and sidebar controls. |
| **Application** | **Python 3.11+** | Core business logic, intent routing, and coordination between components (`chatbot.py`). |
| **Framework** | **LangChain** | Manages the chain of thought, prompt templates, and RAG context injection. |
| **Model** | **OpenAI / Ollama** | Handles the generation of natural language responses and remediation scripts. |
| **Data** | **FAISS & NIST** | Stores high-dimensional vector embeddings and raw vulnerability JSON data. |
