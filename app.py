"""
Security Chatbot Web Interface
Streamlit-based UI for interacting with the security chatbot
"""

import streamlit as st
import os
from dotenv import load_dotenv
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from chatbot import create_chatbot, LLMInterface
from rag_pipeline import SecurityRAGPipeline, create_sample_infrastructure
from cve_collector import CVEDataCollector

load_dotenv()

# Page configuration
st.set_page_config(
    page_title="Security Chatbot",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #64748B;
        margin-bottom: 2rem;
    }
    .source-box {
        background-color: #F1F5F9;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-top: 1rem;
    }
    .severity-critical {
        color: #DC2626;
        font-weight: 600;
    }
    .severity-high {
        color: #EA580C;
        font-weight: 600;
    }
    .severity-medium {
        color: #D97706;
        font-weight: 600;
    }
    .severity-low {
        color: #059669;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


def initialize_session_state():
    """Initialize Streamlit session state"""
    if 'chatbot' not in st.session_state:
        st.session_state.chatbot = None
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    if 'initialized' not in st.session_state:
        st.session_state.initialized = False


def initialize_chatbot(use_ollama: bool):
    """Initialize the chatbot with progress feedback"""
    with st.spinner("Initializing Security Chatbot..."):
        try:
            chatbot = create_chatbot(use_ollama=use_ollama)
            if chatbot:
                st.session_state.chatbot = chatbot
                st.session_state.initialized = True
                st.success("✅ Chatbot initialized successfully!")
                return True
            else:
                st.error("❌ Failed to initialize chatbot. Please check your configuration.")
                return False
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")
            return False


def refresh_knowledge_base():
    """Refresh CVE data and rebuild knowledge base"""
    with st.spinner("Fetching latest CVE data..."):
        try:
            # Fetch new CVE data
            collector = CVEDataCollector(api_key=os.getenv('NVD_API_KEY'))
            cves = collector.fetch_recent_cves(days=90, max_results=200)
            collector.save_to_file(cves)
            
            # Rebuild knowledge base
            infrastructure = create_sample_infrastructure()
            st.session_state.chatbot.rag.build_knowledge_base(cves, infrastructure)
            st.session_state.chatbot.rag.save_index()
            
            st.success(f"✅ Knowledge base updated with {len(cves)} CVEs!")
            return True
        except Exception as e:
            st.error(f"❌ Error updating knowledge base: {str(e)}")
            return False


def display_chat_message(role: str, content: str, sources: list = None):
    """Display a chat message with optional sources"""
    with st.chat_message(role):
        st.markdown(content)
        if sources and len(sources) > 0:
            with st.expander("📚 Sources", expanded=False):
                for source in sources:
                    st.markdown(f"- {source}")


def main():
    """Main application"""
    initialize_session_state()
    
    # Header
    st.markdown('<h1 class="main-header">🔒 Security Chatbot</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">AI-Powered Vulnerability Analysis and Security Recommendations</p>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # LLM Selection
        st.subheader("LLM Settings")
        use_ollama = st.checkbox(
            "Use Ollama (Local)",
            value=os.getenv('USE_OLLAMA', 'false').lower() == 'true',
            help="Use local Ollama instead of OpenAI API. Requires Ollama to be installed and running."
        )

        if use_ollama:
            ollama_model = st.text_input(
                "Ollama Model",
                value=os.getenv('OLLAMA_MODEL', 'llama2:latest'),
                help="Name of the Ollama model to use (e.g., llama2:latest, gemma2:latest)"
            )
            if ollama_model:
                os.environ['OLLAMA_MODEL'] = ollama_model
        
        if not use_ollama:
            openai_key = st.text_input(
                "OpenAI API Key",
                type="password",
                value=os.getenv('OPENAI_API_KEY', ''),
                help="Enter your OpenAI API key"
            )
            if openai_key:
                os.environ['OPENAI_API_KEY'] = openai_key
        
        st.divider()
        
        # Initialize/Restart button
        if st.button("🚀 Initialize Chatbot", use_container_width=True):
            initialize_chatbot(use_ollama)
        
        # Refresh knowledge base button
        if st.session_state.initialized:
            if st.button("🔄 Update CVE Database", use_container_width=True):
                refresh_knowledge_base()
        
        st.divider()
        
        # Knowledge base info
        st.subheader("📊 Knowledge Base Info")
        if st.session_state.chatbot and st.session_state.chatbot.rag.index:
            num_docs = len(st.session_state.chatbot.rag.documents)
            st.metric("Documents", num_docs)
            
            # CVE count
            cve_count = sum(1 for m in st.session_state.chatbot.rag.metadata if m.get('source') == 'cve')
            st.metric("CVE Records", cve_count)
        else:
            st.info("Knowledge base not loaded")
        
        st.divider()
        
        # Clear history button
        if st.button("🗑️ Clear Chat History", use_container_width=True):
            st.session_state.chat_history = []
            if st.session_state.chatbot:
                st.session_state.chatbot.clear_history()
            st.rerun()
        
        st.divider()
        
        # About
        with st.expander("ℹ️ About"):
            st.markdown("""
            **Security Chatbot** uses RAG (Retrieval-Augmented Generation) 
            to provide accurate security analysis based on:
            
            - Latest CVE data from NIST NVD
            - Infrastructure vulnerability assessment
            - Security best practices
            
            **Tech Stack:**
            - LLM: OpenAI GPT-3.5 or Ollama
            - Embeddings: sentence-transformers
            - Vector Store: FAISS
            - Framework: LangChain
            """)
    
    # Main chat interface
    if not st.session_state.initialized:
        st.info("👈 Please initialize the chatbot using the sidebar configuration.")
        
        # Quick start guide
        with st.expander("🚀 Quick Start Guide", expanded=True):
            st.markdown("""
            ### Setup Instructions:
            
            **Option 1: Using OpenAI (Recommended)**
            1. Get an API key from [OpenAI Platform](https://platform.openai.com/api-keys)
            2. Enter your API key in the sidebar
            3. Click "Initialize Chatbot"
            
            **Option 2: Using Ollama (Free, Local)**
            1. Install Ollama from [ollama.ai](https://ollama.ai)
            2. Run: `ollama pull llama2`
            3. Run: `ollama serve`
            4. Check "Use Ollama" in sidebar
            5. Click "Initialize Chatbot"
            
            ### Sample Questions:
            - What are the most critical vulnerabilities in our infrastructure?
            - How can we protect against recent Apache vulnerabilities?
            - What security measures should we implement for our web servers?
            - Tell me about CVE-2024-XXXXX and its impact
            """)
        
        return
    
    # Display chat history
    for message in st.session_state.chat_history:
        display_chat_message("user", message["query"])
        display_chat_message("assistant", message["response"], message.get("sources"))
    
    # Chat input
    user_input = st.chat_input("Ask a security question...")
    
    if user_input:
        # Add user message to history
        st.session_state.chat_history.append({
            "query": user_input,
            "response": "",
            "sources": []
        })
        
        # Display user message
        display_chat_message("user", user_input)
        
        # Generate response
        with st.chat_message("assistant"):
            with st.spinner("Analyzing..."):
                try:
                    result = st.session_state.chatbot.chat(user_input)
                    response = result["response"]
                    sources = result["sources"]
                    
                    # Display response
                    st.markdown(response)
                    
                    # Display sources
                    if sources and len(sources) > 0:
                        with st.expander("📚 Sources", expanded=False):
                            for source in sources:
                                st.markdown(f"- {source}")
                    
                    # Update history
                    st.session_state.chat_history[-1]["response"] = response
                    st.session_state.chat_history[-1]["sources"] = sources
                    
                except Exception as e:
                    error_msg = f"Error generating response: {str(e)}"
                    st.error(error_msg)
                    st.session_state.chat_history[-1]["response"] = error_msg
    
    # Suggested questions
    if len(st.session_state.chat_history) == 0:
        st.markdown("### 💡 Suggested Questions:")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔍 What are critical vulnerabilities in our systems?", use_container_width=True):
                st.session_state.user_input = "What are the most critical vulnerabilities affecting our infrastructure?"
                st.rerun()
            
            if st.button("🛡️ How to protect web servers?", use_container_width=True):
                st.session_state.user_input = "What security measures should we implement for our Apache web servers?"
                st.rerun()
        
        with col2:
            if st.button("⚠️ Recent high-severity CVEs", use_container_width=True):
                st.session_state.user_input = "Show me recent high-severity CVEs that affect common server software"
                st.rerun()
            
            if st.button("📊 Risk assessment", use_container_width=True):
                st.session_state.user_input = "Perform a risk assessment of our current infrastructure"
                st.rerun()


if __name__ == "__main__":
    main()
