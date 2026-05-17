import json
import hashlib
import requests
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv("/home/james-warren/Projects/Vektasafe Projects/octio/.env")

API_KEY = os.getenv("OPENROUTER_API_KEY").strip('"')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "google/gemma-3-27b-it"

def load_registry():
    with open("/home/james-warren/Projects/Vektasafe Projects/octio/registry.json") as f:
        data = json.load(f)
    return data["indicators"]

def hash_target(url_or_address):
    if url_or_address.startswith("http"):
        parts = url_or_address.split("/")
        domain = parts[2] if len(parts) > 2 else url_or_address
    else:
        domain = url_or_address
    return hashlib.sha256(domain.encode()).hexdigest()[:16]

def query_registry(target, registry):
    target_hash = hash_target(target)
    if target_hash in registry:
        ind = registry[target_hash]
        return {
            "flagged": True,
            "target_hash": target_hash,
            "severity": ind["severity"],
            "indicator_type": ind["indicator_type"],
            "reasoning": ind["reasoning"],
            "timestamp": ind["timestamp"]
        }
    return {
        "flagged": False,
        "target_hash": target_hash,
        "severity": None,
        "indicator_type": None,
        "reasoning": None,
        "timestamp": None
    }

def gemma_risk_assessment(target, query_result):
    if not query_result["flagged"]:
        prompt = f"""You are a DeFi security oracle. A protocol is about to interact with:
Target: {target}

This target is NOT in the threat registry. Based on the domain or address pattern alone, assess the risk.

Respond in JSON only:
{{
    "risk_level": "SAFE" or "SUSPICIOUS" or "UNKNOWN",
    "recommendation": "PROCEED" or "CAUTION" or "BLOCK",
    "reasoning": "one sentence"
}}"""
    else:
        prompt = f"""You are a DeFi security oracle. A protocol is about to interact with:
Target: {target}

This target IS in the threat registry with the following data:
- Severity: {query_result['severity']}
- Type: {query_result['indicator_type']}
- Reasoning: {query_result['reasoning']}

Provide a final risk assessment for the protocol.

Respond in JSON only:
{{
    "risk_level": "HIGH" or "CRITICAL",
    "recommendation": "BLOCK",
    "reasoning": "one sentence"
}}"""

    response = requests.post(
        OPENROUTER_URL,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": MODEL,
            "messages": [{"role": "user", "content": prompt}]
        }
    )

    content = response.json()["choices"][0]["message"]["content"].strip()
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    return json.loads(content.strip())

def run_oracle(targets):
    registry = load_registry()
    print("\n=== OCTIO Oracle Interface ===")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Registry size: {len(registry)} indicators\n")

    results = []
    for target in targets:
        print(f"Query: {target}")
        query_result = query_registry(target, registry)
        assessment = gemma_risk_assessment(target, query_result)

        result = {
            "target": target,
            "target_hash": query_result["target_hash"],
            "in_registry": query_result["flagged"],
            "registry_severity": query_result["severity"],
            "gemma_assessment": assessment,
            "timestamp": datetime.now().isoformat()
        }
        results.append(result)

        status = "FLAGGED" if query_result["flagged"] else "NOT IN REGISTRY"
        print(f"  Registry: {status}")
        print(f"  Risk Level: {assessment['risk_level']}")
        print(f"  Recommendation: {assessment['recommendation']}")
        print(f"  Reasoning: {assessment['reasoning']}\n")

    with open("/home/james-warren/Projects/Vektasafe Projects/octio/oracle_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"Oracle results saved to oracle_results.json")
    return results

if __name__ == "__main__":
    test_targets = [
        "http://www.dpdlocoqu.cyou/com",
        "https://uniswap.org",
        "http://metamask-security-alert.com/connect",
        "https://aave.com",
        "http://instagram.com.universal-api.org/"
    ]
    run_oracle(test_targets)
