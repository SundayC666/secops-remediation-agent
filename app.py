"""
Security Chatbot Web Interface
Features:
1. Card-based UI for Vulnerability Analysis (JSON Rendering)
2. Excel-like Asset Management
3. Auto-scrolling & Static Footer
"""

import streamlit as st
import os
import json
import pandas as pd
import streamlit.components.v1 as components
from dotenv import load_dotenv
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from chatbot import create_chatbot
from cve_collector import CVEDataCollector
from email_utils import parse_eml_file

load_dotenv()

st.set_page_config(page_title="SecOps Remediation Agent", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# --- CSS for "Card-like" UI ---
st.markdown("""
<style>
    .main-header { font-size: 2.5rem; font-weight: 700; color: #1E3A8A; margin-bottom: 0.5rem; }
    
    /* Card Styling */
    .finding-card {
        background-color: #f8f9fa;
        border-left: 5px solid #ddd;
        padding: 15px;
        margin-bottom: 10px;
        border-radius: 5px;
    }
    
    /* Footer */
    .footer {
        width: 100%;
        font-size: 0.8rem;
        color: #888;
        text-align: center;
        padding: 20px;
        margin-top: 50px;
        border-top: 1px solid #eee;
    }
</style>
""", unsafe_allow_html=True)

# Javascript for Auto-Scroll
def scroll_to_bottom():
    js = """
    <script>
        var body = window.parent.document.querySelector(".main");
        body.scrollTop = body.scrollHeight;
    </script>
    """
    components.html(js, height=0)

def initialize_chatbot(use_ollama: bool):
    with st.spinner("Initializing system..."):
        cb = create_chatbot(use_ollama=use_ollama)
        if cb:
            st.session_state.chatbot = cb
            st.session_state.initialized = True
            st.success("System Online")

def rebuild_index():
    with st.spinner("Rebuilding knowledge base..."):
        try:
            infra = st.session_state.chatbot.rag.load_infrastructure_context()
            collector = CVEDataCollector()
            cves = collector.load_from_file()
            if not cves: cves = collector.fetch_recent_cves(days=90, max_results=200)
            st.session_state.chatbot.rag.build_knowledge_base(cves, infra)
            st.session_state.chatbot.rag.save_index()
            st.success("Knowledge Base Updated!")
        except Exception as e: st.error(f"Error: {e}")

# --- UI RENDERING ENGINE ---
def render_security_response(response_text):
    """Parses JSON response and renders it as UI Components (Cards/Metrics)"""
    try:
        data = json.loads(response_text)
    except json.JSONDecodeError:
        # Fallback if LLM fails to generate JSON
        st.markdown(response_text)
        return

    # 1. Executive Summary Banner
    sev = data.get("highest_severity", "INFO").upper()
    summary = data.get("summary", "Analysis complete.")
    
    if sev == "CRITICAL":
        st.error(f"🚨 **CRITICAL ALERT:** {summary}", icon="🚨")
    elif sev == "HIGH":
        st.warning(f"⚠️ **HIGH RISK:** {summary}", icon="⚠️")
    elif sev == "SAFE":
        st.success(f"✅ **SYSTEM SAFE:** {summary}", icon="✅")
    else:
        st.info(f"ℹ️ **STATUS:** {summary}", icon="ℹ️")

    # 2. Action Plan (Checklist & CSV Download)
    if data.get("action_plan"):
        with st.expander("📝 **Immediate Action Plan (To-Do)**", expanded=True):
            # Create a list for the CSV
            action_items = data["action_plan"]
            
            # Display Checkboxes
            for action in action_items:
                st.checkbox(action)
            
            # --- NEW: Download Button ---
            st.divider()
            # Convert list to DataFrame
            df_actions = pd.DataFrame(action_items, columns=["Action Item"])
            # Add a 'Status' column for the user to fill in later
            df_actions["Status"] = "Pending"
            df_actions["Assignee"] = ""
            
            csv = df_actions.to_csv(index=False).encode('utf-8')
            
            st.download_button(
                label="📥 Download Action Plan (CSV)",
                data=csv,
                file_name="security_remediation_plan.csv",
                mime="text/csv",
                help="Download this checklist to track remediation progress."
            )

    st.divider()

    # 3. Findings Cards
    st.subheader("🔍 Technical Findings & Recommendations")
    findings = data.get("findings", [])
    
    if not findings:
        st.caption("No specific technical findings reported.")
    
    for item in findings:
        cve = item.get("cve", "N/A")
        
        # UI Layout for Card
        with st.container():
            # Apply styling via CSS class (defined in main)
            st.markdown('<div class="finding-card">', unsafe_allow_html=True)
            
            col1, col2 = st.columns([3, 1])
            with col1:
                # Title Logic
                if cve != "N/A" and cve is not None:
                    st.markdown(f"#### 🔴 {item.get('title', 'Vulnerability detected')}")
                    st.caption(f"**CVE ID:** {cve}")
                else:
                    # For General Knowledge Items
                    st.markdown(f"#### 🛡️ {item.get('title', 'Best Practice')}")
                
                st.markdown(f"**Description:** {item.get('description')}")
                st.markdown(f"**Affected Assets:** `{item.get('affected_assets', 'General')}`")
            
            with col2:
                # Remediation Box
                st.markdown("##### 🛠️ Fix / Action")
                st.info(item.get("remediation", "See details"))
                
                if item.get("patch_link"):
                    st.link_button("Download Patch 🔗", item["patch_link"])
                
                if item.get("kev"):
                    st.error("🔥 Active Exploit")
            
            st.markdown('</div>', unsafe_allow_html=True)
            st.divider()

def main():
    if 'chatbot' not in st.session_state: st.session_state.chatbot = None
    if 'chat_history' not in st.session_state: st.session_state.chat_history = []
    if 'initialized' not in st.session_state: st.session_state.initialized = False

    st.markdown('<h1 class="main-header">🛡️ SecOps Remediation Agent</h1>', unsafe_allow_html=True)

    # --- SIDEBAR: ASSET MANAGEMENT ---
    with st.sidebar:
        st.header("⚙️ Settings")
        use_ollama = st.checkbox("Use Ollama (Local)", value=os.getenv('USE_OLLAMA', 'false').lower() == 'true')
        if not use_ollama:
            openai_key = st.text_input("OpenAI Key", type="password", value=os.getenv('OPENAI_API_KEY', ''))
            if openai_key: os.environ['OPENAI_API_KEY'] = openai_key
            
        if st.button("🚀 Initialize System", use_container_width=True): initialize_chatbot(use_ollama)
        st.divider()
        
        st.header("🏢 Asset Inventory")
        with st.expander("Manage Assets", expanded=False):
            infra_file = "data/infrastructure.json"
            if os.path.exists(infra_file):
                with open(infra_file, "r") as f:
                    infra_data = json.load(f)
                df = pd.DataFrame(infra_data)
            else:
                df = pd.DataFrame(columns=["id", "name", "details"])

            edited_df = st.data_editor(df, num_rows="dynamic", use_container_width=True)

            if st.button("💾 Save & Rebuild Context"):
                try:
                    json_data = edited_df.to_dict(orient="records")
                    os.makedirs("data", exist_ok=True)
                    with open(infra_file, "w") as f:
                        json.dump(json_data, f, indent=2)
                    
                    if st.session_state.initialized: rebuild_index()
                    st.success("Assets Saved!")
                except Exception as e: st.error(f"Error saving: {e}")

    if not st.session_state.initialized:
        st.info("👈 Please initialize the agent from the sidebar.")
        return

    tab1, tab2 = st.tabs(["💬 Vulnerability Chat", "🕵️ Phishing Analyzer"])

    # --- TAB 1: Chat ---
    with tab1:
        # Render History
        for msg in st.session_state.chat_history:
            with st.chat_message("user"):
                st.write(msg["query"])
            
            with st.chat_message("assistant"):
                mode = msg.get("mode")
                if mode == 'General Knowledge': st.caption("🧠 **General Knowledge**")
                else: st.caption("🗄️ **Internal Database Match**")
                
                render_security_response(msg["response"])
                
                sources = msg.get("sources")
                if sources:
                    with st.expander("📚 Sources & Intelligence"):
                        for source in sources: st.markdown(f"- {source}")

        # Chat Input (Bottom)
        if user_input := st.chat_input("Ex: 'Is my Ubuntu server at risk?'"):
            st.session_state.chat_history.append({"query": user_input, "response": "", "sources": [], "mode": "Pending"})
            
            with st.chat_message("user"):
                st.write(user_input)
            
            with st.chat_message("assistant"):
                with st.spinner("Analyzing against Infrastructure & Threat Intel..."):
                    result = st.session_state.chatbot.chat(user_input)
                    response = result["response"]
                    sources = result["sources"]
                    mode = result["mode"]
                    
                    if mode == 'General Knowledge': st.caption("🧠 **General Knowledge**")
                    else: st.caption("🗄️ **Internal Database Match**")
                    
                    render_security_response(response)
                    
                    if sources:
                        with st.expander("📚 Sources & Intelligence"):
                            for source in sources: st.markdown(f"- {source}")
                    
                    st.session_state.chat_history[-1].update({"response": response, "sources": sources, "mode": mode})
            
            scroll_to_bottom()

    # --- TAB 2: Phishing (Keep as is) ---
    with tab2:
        st.markdown("### ☁️ Cloud Airlock: Phishing Sandbox")
        uploaded_file = st.file_uploader("Upload .eml", type=['eml'])
        if uploaded_file:
            email_data = parse_eml_file(uploaded_file)
            if email_data:
                col1, col2 = st.columns(2)
                col1.info(f"From: {email_data['from']}")
                col2.info(f"Subject: {email_data['subject']}")
                with st.expander("Body"): st.text(email_data['body'])
                if st.button("🤖 AI Analysis"):
                    with st.spinner("Scanning..."):
                        prompt = """Analyze for phishing. Return JSON: {"verdict": "SAFE/SUSPICIOUS/MALICIOUS", "risk_score": 0-10, "summary": "text", "recommendation": "text", "indicators": [{"type": "Link/Sender", "value": "x", "status": "Safe/Risk"}]}"""
                        task = f"Metadata: {email_data['from']}, {email_data['subject']}\nBody: {email_data['body'][:3000]}\nLinks: {email_data['links']}"
                        res = st.session_state.chatbot.chat(task, include_context=False, custom_system_prompt=prompt)
                        try:
                            analysis = json.loads(res['response'].replace("```json","").replace("```","").strip())
                            st.divider()
                            color = st.success if analysis['verdict']=="SAFE" else st.error
                            color(f"**VERDICT: {analysis['verdict']}** ({analysis['risk_score']}/10)\n\n{analysis.get('recommendation')}")
                            if analysis.get('indicators'): st.dataframe(pd.DataFrame(analysis['indicators']), use_container_width=True, hide_index=True)
                        except: st.write(res['response'])

    # --- Static Footer ---
    st.markdown("""
    <div class="footer">
    This tool uses data from the CISA Known Exploited Vulnerabilities Catalog (CC0 1.0). <br>
    This project is not endorsed by CISA or DHS.
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()