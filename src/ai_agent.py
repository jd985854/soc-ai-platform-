import time
from langchain_community.llms import Ollama
from langchain_core.prompts import PromptTemplate

# Initialize the local LLM (runs on your CPU/GPU)
llm = Ollama(model="llama3.2:3b", temperature=0.1)

def multi_agent_consensus(vuln, correlation):
    """
    REAL AI Multi-Agent Consensus using Ollama LLM.
    This takes ~5-10 seconds per vulnerability on a laptop.
    """
    
    # --- AGENT 1: Security Analyst ---
    exploit_prompt = PromptTemplate.from_template(
        """You are a Security Analyst. Analyze this vulnerability and determine if it is a TRUE POSITIVE or FALSE POSITIVE.
        CVE: {cve}
        Description: {desc}
        CVSS Score: {score}
        Answer only TRUE POSITIVE or FALSE POSITIVE with a short reason."""
    )
    chain_sec = exploit_prompt | llm
    sec_result = chain_sec.invoke({"cve": vuln['cve'], "desc": vuln['description'], "score": vuln['cvss_score']})
    
    # --- AGENT 2: Context Specialist ---
    context_prompt = PromptTemplate.from_template(
        """You are a Context Specialist. Is this asset REACHABLE and CRITICAL?
        Host: {host}
        Port: {port}
        Environment: {env}
        Answer only REACHABLE or UNREACHABLE with a short reason."""
    )
    chain_ctx = context_prompt | llm
    ctx_result = chain_ctx.invoke({"host": vuln['host'], "port": vuln['port'], "env": vuln.get('environment', 'unknown')})
    
    # --- AGENT 3: Impact Validator ---
    impact_prompt = PromptTemplate.from_template(
        """You are an Impact Validator. What is the business risk?
        CVSS Score: {score}
        Suspicious Logs Found: {log_count}
        Answer only HIGH RISK, MEDIUM RISK, or LOW RISK with a short reason."""
    )
    chain_imp = impact_prompt | llm
    imp_result = chain_imp.invoke({"score": vuln['cvss_score'], "log_count": correlation['suspicious_entries']})
    
    # --- AGENT 4: Consensus Aggregator (Parsing Logic) ---
    # Parse the text responses to determine the final verdict
    is_true = "TRUE POSITIVE" in sec_result.upper()
    is_reachable = "REACHABLE" in ctx_result.upper()
    is_high_risk = "HIGH" in imp_result.upper()
    
    # Simple voting: 2 out of 3 must agree
    votes = [is_true, is_reachable, is_high_risk]
    true_votes = sum(votes)
    
    if true_votes >= 2:
        final_verdict = "TRUE POSITIVE"
    else:
        final_verdict = "FALSE POSITIVE"
    
    # Calculate confidence based on number of agreeing votes
    confidence = round((true_votes / 3) * 100, 2)
    
    return {
        'final_verdict': final_verdict,
        'confidence': confidence,
        'security_agent': sec_result.strip()[:100],
        'context_agent': ctx_result.strip()[:100],
        'impact_agent': imp_result.strip()[:100],
        'reasoning': f"Votes: {true_votes}/3. Sec: {sec_result[:50]}..."
    }
