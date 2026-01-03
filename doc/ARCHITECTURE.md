# Security Chatbot - System Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                          │
│                      (Streamlit Web App)                        │
│  - Query Input                                                  │
│  - Chat Display                                                 │
│  - Configuration Panel                                          │
│  - Knowledge Base Management                                    │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SECURITY CHATBOT                           │
│                        (chatbot.py)                             │
│  - Query Processing                                             │
│  - Context Integration                                          │
│  - Response Generation                                          │
│  - Source Attribution                                           │
└──────────────┬────────────────────────────┬─────────────────────┘
               │                            │
               ▼                            ▼
┌──────────────────────────┐    ┌──────────────────────────┐
│     RAG PIPELINE         │    │    LLM INTERFACE         │
│   (rag_pipeline.py)      │    │    (chatbot.py)          │
│                          │    │                          │
│  - Text Chunking         │    │  Options:                │
│  - Embedding Generation  │    │  1. OpenAI GPT-3.5      │
│  - Vector Indexing       │    │  2. Ollama Llama 2      │
│  - Similarity Search     │    │                          │
└───────────┬──────────────┘    └──────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    KNOWLEDGE BASE                               │
│                                                                 │
│  ┌─────────────────────┐        ┌─────────────────────┐       │
│  │  VECTOR STORE       │        │   CVE DATABASE      │       │
│  │  (FAISS Index)      │        │   (cve_collector.py)│       │
│  │                     │        │                     │       │
│  │  - Document Chunks  │        │  - CVE Records      │       │
│  │  - Embeddings       │        │  - CVSS Scores      │       │
│  │  - Metadata         │        │  - Descriptions     │       │
│  └─────────────────────┘        │  - Affected Products│       │
│                                  └─────────┬───────────┘       │
│                                            │                   │
│  ┌─────────────────────┐                  │                   │
│  │  INFRASTRUCTURE DB  │                  │                   │
│  │  (Sample Data)      │                  │                   │
│  │                     │◄─────────────────┘                   │
│  │  - Server Configs   │                                      │
│  │  - OS Versions      │                                      │
│  │  - Services         │                                      │
│  │  - Network Info     │                                      │
│  └─────────────────────┘                                      │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    EXTERNAL DATA SOURCES                        │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │         NIST National Vulnerability Database             │  │
│  │              https://nvd.nist.gov/                       │  │
│  │  - CVE Records                                           │  │
│  │  - Real-time Updates                                     │  │
│  │  - RESTful API                                           │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagram

```
┌────────────┐
│   User     │
│   Query    │
└─────┬──────┘
      │
      ▼
┌─────────────────────────────────────┐
│  1. Query Embedding                 │
│     (sentence-transformers)         │
│     "What are Apache vulns?"        │
│            ↓                        │
│     [0.23, 0.45, 0.12, ...]        │
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
│     Doc2: CVE-2024-5678 (Score:0.8) │
│     Doc3: Apache Config (Score:0.7) │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  3. Context Assembly                │
│     Combine:                        │
│     - User Query                    │
│     - Retrieved Documents           │
│     - System Instructions           │
│            ↓                        │
│     Complete Prompt                 │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  4. LLM Generation                  │
│     (OpenAI GPT-3.5 / Ollama)       │
│     - Process Context               │
│     - Generate Response             │
│     - Extract Sources               │
│            ↓                        │
│     Generated Answer + Citations    │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  5. Response Formatting             │
│     - Main Response Text            │
│     - Source Citations (CVE IDs)    │
│     - Relevance Metadata            │
└─────────────┬───────────────────────┘
              │
              ▼
┌────────────────┐
│  Display to    │
│     User       │
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
    │   └─→ chatbot.py::SecurityChatbot.chat()
    │       ├─→ rag_pipeline.py::retrieve()
    │       │   └─→ FAISS similarity search
    │       └─→ LLMInterface::generate_response()
    │           └─→ OpenAI API / Ollama
    │
    └─→ Display Response
        ├─→ Response Text
        └─→ Source Citations
```

## File Dependencies

```
app.py
  │
  ├── imports chatbot.py
  │     │
  │     ├── imports rag_pipeline.py
  │     │     │
  │     │     ├── imports sentence_transformers
  │     │     ├── imports faiss
  │     │     └── imports langchain
  │     │
  │     ├── imports cve_collector.py
  │     │     │
  │     │     └── imports requests
  │     │
  │     └── imports openai / ollama
  │
  └── imports streamlit
```

## Data Storage Structure

```
security_chatbot/
├── data/                           # CVE data storage
│   └── cve_data.json              # Fetched CVE records
│
├── vector_store/                   # FAISS index storage
│   ├── faiss_index.bin            # Vector index
│   └── documents.pkl              # Document metadata
│
└── .env                           # Configuration
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

## Query Processing Flow

```
User Query: "What are Apache vulnerabilities?"
      │
      ▼
[Embedding] → [0.12, 0.34, 0.56, ..., 0.78]
      │
      ▼
[FAISS Search] → Top 5 Similar Vectors
      │
      ├─→ Doc1: "CVE-2024-1234 affects Apache 2.4.x" (score: 0.89)
      ├─→ Doc2: "Apache security configuration..." (score: 0.82)
      ├─→ Doc3: "CVE-2024-5678 Apache DoS..." (score: 0.78)
      ├─→ Doc4: "Web Server Cluster: Apache 2.4.52" (score: 0.75)
      └─→ Doc5: "Apache module vulnerabilities..." (score: 0.71)
      │
      ▼
[Context Assembly]
      │
      ├─→ System Prompt: "You are a cybersecurity expert..."
      ├─→ Context Docs: [Doc1, Doc2, Doc3, Doc4, Doc5]
      └─→ User Query: "What are Apache vulnerabilities?"
      │
      ▼
[LLM Processing]
      │
      ├─→ Analyze Context
      ├─→ Extract Relevant Info
      ├─→ Generate Response
      └─→ Add Citations
      │
      ▼
[Response]
"Based on recent CVE data, Apache web servers face several
critical vulnerabilities:

1. CVE-2024-1234 (CRITICAL - 9.8)
   - Affects: Apache HTTP Server 2.4.x
   - Impact: Remote code execution
   - Recommendation: Upgrade to 2.4.58+

2. CVE-2024-5678 (HIGH - 8.1)
   ..."

Sources: CVE-2024-1234 (CRITICAL), CVE-2024-5678 (HIGH)
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
      ├─→ Test 4: Chatbot Integration
      │   └─→ chatbot.py::SecurityChatbot
      │       ├─→ End-to-end query
      │       └─→ Response validation
      │
      └─→ Test 5: Evaluation Metrics
          └─→ Calculate precision/recall
```

## Technology Stack Layers

```
┌──────────────────────────────────────────┐
│         Presentation Layer               │
│         (Streamlit)                      │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│         Application Layer                │
│    (chatbot.py, rag_pipeline.py)        │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│         Framework Layer                  │
│  (LangChain, sentence-transformers)     │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│         Model Layer                      │
│    (OpenAI API, Ollama, FAISS)          │
└──────────────┬───────────────────────────┘
               │
┌──────────────▼───────────────────────────┐
│         Data Layer                       │
│  (CVE Database, Vector Store, Files)    │
└──────────────────────────────────────────┘
```
