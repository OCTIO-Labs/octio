import json
import requests
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv("/home/james-warren/Projects/Vektasafe Projects/octio/.env")

API_KEY = os.getenv("OPENROUTER_API_KEY").strip('"')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "google/gemma-3-27b-it"

# Documented real-world Web3 incidents involving Web2 attack vectors
DOCUMENTED_INCIDENTS = [
    {
        "name": "Ronin Network Hack",
        "date": "March 2022",
        "loss_usd": 625000000,
        "attack_vector": "PHISHING",
        "description": "Developer phished via fake job offer, private keys compromised",
        "indicators": ["phishing", "social engineering", "credential theft"]
    },
    {
        "name": "Curve Finance DNS Hijack",
        "date": "August 2022",
        "loss_usd": 570000,
        "attack_vector": "DNS_HIJACK",
        "description": "DNS records hijacked, users redirected to malicious frontend",
        "indicators": ["dns hijack", "malicious frontend", "domain compromise"]
    },
    {
        "name": "Ledger Connect Kit Supply Chain",
        "date": "December 2023",
        "loss_usd": 600000,
        "attack_vector": "SUPPLY_CHAIN",
        "description": "Malicious code injected into npm package used by DeFi frontends",
        "indicators": ["supply chain", "npm compromise", "malicious package"]
    },
    {
        "name": "MyEtherWallet BGP Hijack",
        "date": "April 2018",
        "loss_usd": 17000000,
        "attack_vector": "BGP_ANOMALY",
        "description": "BGP routing manipulation redirected traffic to attacker infrastructure",
        "indicators": ["bgp hijack", "routing attack", "dns compromise"]
    },
    {
        "name": "Mixin Network Cloud Breach",
        "date": "September 2023",
        "loss_usd": 200000000,
        "attack_vector": "SUPPLY_CHAIN",
        "description": "Cloud service provider database compromised, private keys exposed",
        "indicators": ["cloud misconfiguration", "credential exposure", "infrastructure breach"]
    }
]

def correlate_with_gemma(indicators, incidents):
    indicators_summary = json.dumps([{
        "type": ind["indicator_type"],
        "severity": ind["severity"],
        "target": ind["target"],
        "reasoning": ind["reasoning"]
    } for ind in indicators], indent=2)

    incidents_summary = json.dumps([{
        "name": inc["name"],
        "attack_vector": inc["attack_vector"],
        "loss_usd": inc["loss_usd"],
        "indicators": inc["indicators"]
    } for inc in incidents], indent=2)

    prompt = f"""You are a threat intelligence analyst for OCTIO, a Web3 security system.

Below are CURRENT threat indicators detected by the OCTIO monitoring layer:
{indicators_summary}

Below are DOCUMENTED real-world Web3 incidents involving Web2 attack vectors:
{incidents_summary}

Analyse the correlation between the current indicators and historical incidents.
Which incident patterns do the current indicators most closely match?
What is the risk to DeFi protocols right now based on this correlation?

Respond in JSON only:
{{
    "high_correlation_incidents": ["list of incident names that match current patterns"],
    "primary_attack_pattern": "description of the dominant attack pattern",
    "risk_to_defi": "HIGH" or "CRITICAL",
    "affected_platforms": ["list of DeFi platforms most at risk"],
    "recommended_actions": ["list of 3 specific actions DeFi protocols should take now"],
    "analyst_summary": "2-3 sentence summary for the dashboard"
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

def run_correlation():
    with open("/home/james-warren/Projects/Vektasafe Projects/octio/registry.json") as f:
        registry_data = json.load(f)

    indicators = list(registry_data["indicators"].values())

    print("\n=== OCTIO Incident Correlation Engine ===")
    print(f"Analysing {len(indicators)} indicators against {len(DOCUMENTED_INCIDENTS)} documented incidents")
    print("Running Gemma 4 correlation analysis...\n")

    correlation = correlate_with_gemma(indicators, DOCUMENTED_INCIDENTS)

    print("HIGH CORRELATION INCIDENTS:")
    for inc in correlation["high_correlation_incidents"]:
        matched = next((i for i in DOCUMENTED_INCIDENTS if i["name"] == inc), None)
        if matched:
            print(f"  {inc} -- Loss: ${matched['loss_usd']:,} USD -- Vector: {matched['attack_vector']}")

    print(f"\nPRIMARY ATTACK PATTERN:")
    print(f"  {correlation['primary_attack_pattern']}")

    print(f"\nRISK TO DEFI: {correlation['risk_to_defi']}")

    print(f"\nAFFECTED PLATFORMS:")
    for platform in correlation["affected_platforms"]:
        print(f"  {platform}")

    print(f"\nRECOMMENDED ACTIONS:")
    for action in correlation["recommended_actions"]:
        print(f"  {action}")

    print(f"\nANALYST SUMMARY:")
    print(f"  {correlation['analyst_summary']}")

    output = {
        "timestamp": datetime.now().isoformat(),
        "indicators_analysed": len(indicators),
        "incidents_compared": len(DOCUMENTED_INCIDENTS),
        "correlation_results": correlation,
        "documented_incidents": DOCUMENTED_INCIDENTS
    }

    with open("/home/james-warren/Projects/Vektasafe Projects/octio/correlation.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nCorrelation report saved to correlation.json")
    return output

if __name__ == "__main__":
    run_correlation()
