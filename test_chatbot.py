"""
Comprehensive Test Script for Security Chatbot
Tests all components and demonstrates functionality
"""

import os
import sys
import time
from typing import List, Dict
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cve_collector import CVEDataCollector
from rag_pipeline import SecurityRAGPipeline, create_sample_infrastructure
from chatbot import LLMInterface, SecurityChatbot

def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def test_cve_collector():
    """Test CVE data collection from NVD"""
    print_section("TEST 1: CVE Data Collection")
    
    collector = CVEDataCollector()
    
    # Test fetching recent CVEs (Increased range to ensure data availability)
    print("Fetching recent CVEs (last 30 days)...")
    start_time = time.time()
    cves = collector.fetch_recent_cves(days=30, max_results=20)
    elapsed = time.time() - start_time
    
    if cves:
        print(f"✅ Successfully fetched {len(cves)} CVEs in {elapsed:.2f}s")
        
        # Display sample CVE
        sample = cves[0]
        print(f"\nSample CVE:")
        print(f"  ID: {sample['cve_id']}")
        print(f"  Severity: {sample['severity']} (CVSS: {sample['cvss_score']})")
        print(f"  Description: {sample['description'][:150]}...")
        print(f"  Published: {sample['published_date']}")
        
        # Save for later use
        collector.save_to_file(cves, 'test_cves.json')
        return True
    else:
        print("❌ Failed to fetch CVEs")
        return False


def test_rag_pipeline():
    """Test RAG pipeline and vector store"""
    print_section("TEST 2: RAG Pipeline")
    
    # Load CVE data
    collector = CVEDataCollector()
    if os.path.exists('data/test_cves.json'):
        cves = collector.load_from_file('test_cves.json')
    else:
        print("⚠️ No test CVE data found, fetching...")
        cves = collector.fetch_recent_cves(days=30, max_results=20)
        collector.save_to_file(cves, 'test_cves.json')
    
    if not cves:
        print("❌ No CVE data available for testing")
        return False
    
    # Create infrastructure data
    infrastructure = create_sample_infrastructure()
    print(f"Created {len(infrastructure)} infrastructure documents")
    
    # Build RAG pipeline
    print("\nBuilding RAG pipeline...")
    start_time = time.time()
    rag = SecurityRAGPipeline()
    rag.build_knowledge_base(cves, infrastructure)
    elapsed = time.time() - start_time
    
    print(f"✅ Knowledge base built in {elapsed:.2f}s")
    print(f"  Total documents: {len(rag.documents)}")
    print(f"  Vector dimension: {rag.dimension}")
    
    # Test retrieval
    print("\nTesting retrieval...")
    test_queries = [
        "Apache web server vulnerabilities",
        "Windows server security",
        "Critical CVEs",
    ]
    
    for query in test_queries:
        print(f"\n  Query: '{query}'")
        results = rag.retrieve(query, top_k=3)
        
        if results:
            print(f"  ✅ Retrieved {len(results)} documents")
            top_result = results[0]
            print(f"     Top result score: {top_result['relevance_score']:.3f}")
            print(f"     Source: {top_result['metadata'].get('source')}")
        else:
            print(f"  ❌ No results retrieved")
    
    # Save index
    rag.save_index('test_vector_store')
    print("\n✅ Vector store saved successfully")
    
    return True


def test_llm_integration():
    """Test LLM integration"""
    print_section("TEST 3: LLM Integration")
    
    # Check which LLM to use
    use_ollama = os.getenv('USE_OLLAMA', 'false').lower() == 'true'
    
    if use_ollama:
        print("Testing Ollama (Local LLM)...")
        try:
            llm = LLMInterface(use_ollama=True, model="llama2")
            test_prompt = "Explain what a CVE is in one sentence."
            
            print(f"Prompt: {test_prompt}")
            response = llm.generate_response(test_prompt, max_tokens=100)
            print(f"Response: {response}")
            
            if "error" in response.lower():
                print("❌ LLM returned an error")
                return False
            else:
                print("✅ Ollama working correctly")
                return True
                
        except Exception as e:
            print(f"❌ Ollama test failed: {e}")
            print("Make sure Ollama is installed and running (ollama serve)")
            return False
    else:
        # Test OpenAI
        if not os.getenv('OPENAI_API_KEY'):
            print("⚠️ No OpenAI API key found in environment")
            print("Skipping OpenAI test (this is okay if using Ollama)")
            return None
        
        print("Testing OpenAI API...")
        try:
            # UPDATED: Use gpt-4o-mini for testing
            model_name = os.getenv('OPENAI_MODEL_NAME', 'gpt-4o-mini')
            print(f"Using model: {model_name}")
            
            llm = LLMInterface(use_ollama=False, model=model_name)
            test_prompt = "Explain what a CVE is in one sentence."
            
            print(f"Prompt: {test_prompt}")
            response = llm.generate_response(test_prompt, max_tokens=100)
            print(f"Response: {response}")
            
            if "error" in response.lower():
                print("❌ OpenAI returned an error")
                return False
            else:
                print("✅ OpenAI working correctly")
                return True
                
        except Exception as e:
            print(f"❌ OpenAI test failed: {e}")
            return False


def test_chatbot_integration():
    """Test complete chatbot integration"""
    print_section("TEST 4: Chatbot Integration")
    
    # Load or create knowledge base
    rag = SecurityRAGPipeline()
    if rag.load_index('test_vector_store'):
        print("✅ Loaded existing test vector store")
    else:
        print("Building new knowledge base for testing...")
        collector = CVEDataCollector()
        cves = collector.fetch_recent_cves(days=30, max_results=20)
        infrastructure = create_sample_infrastructure()
        rag.build_knowledge_base(cves, infrastructure)
    
    # Initialize LLM
    use_ollama = os.getenv('USE_OLLAMA', 'false').lower() == 'true'
    
    try:
        if use_ollama:
            llm = LLMInterface(use_ollama=True, model="llama2")
        else:
            if not os.getenv('OPENAI_API_KEY'):
                print("⚠️ Skipping chatbot test (no API key)")
                return None
            # UPDATED: Use gpt-4o-mini
            model_name = os.getenv('OPENAI_MODEL_NAME', 'gpt-4o-mini')
            llm = LLMInterface(use_ollama=False, model=model_name)
    except Exception as e:
        print(f"❌ Failed to initialize LLM: {e}")
        return False
    
    # Create chatbot
    chatbot = SecurityChatbot(rag, llm)
    print("✅ Chatbot initialized")
    
    # Test queries
    test_queries = [
        "What are the most critical vulnerabilities in our infrastructure?",
        "How should we protect our web servers?",
        "What is the risk level of our Windows servers?"
    ]
    
    print("\nTesting chatbot with sample queries...\n")
    
    for i, query in enumerate(test_queries, 1):
        print(f"Query {i}: {query}")
        
        try:
            result = chatbot.chat(query)
            response = result['response']
            sources = result['sources']
            
            print(f"Response length: {len(response)} characters")
            print(f"Response preview: {response[:200]}...")
            
            if sources:
                print(f"Sources cited: {', '.join(sources)}")
            
            print("✅ Query processed successfully\n")
            
        except Exception as e:
            print(f"❌ Error processing query: {e}\n")
            return False
    
    print("✅ All chatbot tests passed")
    return True


def test_evaluation_metrics():
    """Test and display evaluation metrics"""
    print_section("TEST 5: Evaluation Metrics")
    
    # Load knowledge base
    rag = SecurityRAGPipeline()
    if not rag.load_index('test_vector_store'):
        print("⚠️ No vector store found, skipping metrics")
        return None
    
    print("Knowledge Base Statistics:")
    print(f"  Total chunks: {len(rag.documents)}")
    print(f"  Vector dimension: {rag.dimension}")
    
    # Count sources
    cve_count = sum(1 for m in rag.metadata if m.get('source') == 'cve')
    infra_count = sum(1 for m in rag.metadata if m.get('source') == 'infrastructure')
    
    print(f"  CVE documents: {cve_count}")
    print(f"  Infrastructure documents: {infra_count}")
    
    # Test retrieval precision
    print("\nRetrieval Quality Test:")
    
    test_cases = [
        {
            'query': 'Apache vulnerabilities',
            'expected_keyword': 'apache'
        },
        {
            'query': 'High severity CVEs',
            'expected_keyword': 'high'
        },
        {
            'query': 'Windows security',
            'expected_keyword': 'windows'
        }
    ]
    
    precision_scores = []
    
    for test in test_cases:
        query = test['query']
        expected = test['expected_keyword'].lower()
        
        results = rag.retrieve(query, top_k=5)
        
        relevant_count = sum(
            1 for r in results 
            if expected in r['content'].lower()
        )
        
        precision = relevant_count / len(results) if results else 0
        precision_scores.append(precision)
        
        print(f"  Query: '{query}'")
        print(f"    Relevant results: {relevant_count}/{len(results)}")
        print(f"    Precision: {precision:.2%}")
    
    avg_precision = sum(precision_scores) / len(precision_scores)
    print(f"\n  Average Precision: {avg_precision:.2%}")
    
    print("\n✅ Evaluation metrics calculated")
    return True


def run_all_tests():
    """Run all tests"""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "SECURITY CHATBOT TEST SUITE" + " "*26 + "║")
    print("╚" + "="*68 + "╝")
    
    results = {}
    
    # Run tests
    results['CVE Collection'] = test_cve_collector()
    results['RAG Pipeline'] = test_rag_pipeline()
    results['LLM Integration'] = test_llm_integration()
    results['Chatbot Integration'] = test_chatbot_integration()
    results['Evaluation Metrics'] = test_evaluation_metrics()
    
    # Summary
    print_section("TEST SUMMARY")
    
    for test_name, result in results.items():
        if result is True:
            status = "✅ PASSED"
        elif result is False:
            status = "❌ FAILED"
        else:
            status = "⚠️ SKIPPED"
        
        print(f"  {test_name:.<50} {status}")
    
    passed = sum(1 for r in results.values() if r is True)
    total = len([r for r in results.values() if r is not None])
    
    print(f"\n  Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  🎉 All tests passed successfully!")
    else:
        print("\n  ⚠️ Some tests failed. Check the output above for details.")
    
    print("\n")


if __name__ == "__main__":
    # Check for .env file
    if not os.path.exists('.env'):
        print("⚠️ WARNING: .env file not found!")
        print("Please create .env file from .env.example")
        print("You need to configure either OpenAI API key or Ollama\n")
    
    run_all_tests()