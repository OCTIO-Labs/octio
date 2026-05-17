import json
import os
import subprocess
from datetime import datetime

def clear():
    os.system('clear')

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None

def print_header():
    print("=" * 70)
    print("  OCTIO -- On-Chain Threat Intelligence Oracle")
    print("  Powered by Gemma 4 (google/gemma-3-27b-it) via OpenRouter")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 70)

def print_indicators(registry):
    if not registry:
        print("No registry data found.")
        return
    indicators = list(registry["indicators"].values())
    print(f"\n[ THREAT INDICATORS ] -- {len(indicators)} validated\n")
    print(f"  {'#':<4} {'TYPE':<15} {'SEVERITY':<10} {'TARGET':<30} {'HASH':<18}")
    print(f"  {'-'*4} {'-'*15} {'-'*10} {'-'*30} {'-'*18}")
    for ind in indicators:
        print(f"  {ind['id']:<4} {ind['indicator_type']:<15} {ind['severity']:<10} {ind['target'][:28]:<30} {ind['target_hash']:<18}")

def print_oracle_results(oracle):
    if not oracle:
        print("No oracle data found.")
        return
    print(f"\n[ ORACLE QUERY RESULTS ] -- {len(oracle)} queries\n")
    for result in oracle:
        status = "BLOCK" if result["gemma_assessment"]["recommendation"] == "BLOCK" else \
                 "CAUTION" if result["gemma_assessment"]["recommendation"] == "CAUTION" else "PROCEED"
        risk = result["gemma_assessment"]["risk_level"]
        target = result["target"][:45]
        print(f"  [{status:<7}] [{risk:<10}] {target}")

def print_correlation(corr):
    if not corr:
        print("No correlation data found.")
        return
    results = corr["correlation_results"]
    print(f"\n[ INCIDENT CORRELATION ] -- Risk Level: {results['risk_to_defi']}\n")
    print(f"  Primary Pattern: {results['primary_attack_pattern'][:65]}")
    print(f"\n  Correlated Incidents:")
    for inc in results["high_correlation_incidents"]:
        matched = next((i for i in corr["documented_incidents"] if i["name"] == inc), None)
        if matched:
            print(f"    {inc} -- ${matched['loss_usd']:,} USD")
    print(f"\n  Analyst Summary:")
    summary = results["analyst_summary"]
    words = summary.split()
    line = "    "
    for word in words:
        if len(line) + len(word) > 68:
            print(line)
            line = "    " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

def print_recommended_actions(corr):
    if not corr:
        return
    results = corr["correlation_results"]
    print(f"\n[ RECOMMENDED ACTIONS ]\n")
    for i, action in enumerate(results["recommended_actions"], 1):
        words = action.split()
        line = f"  {i}. "
        for word in words:
            if len(line) + len(word) > 68:
                print(line)
                line = "     " + word + " "
            else:
                line += word + " "
        if line.strip():
            print(line)

def print_stats(registry, oracle, corr):
    total_indicators = len(registry["indicators"]) if registry else 0
    total_queries = len(oracle) if oracle else 0
    blocked = sum(1 for r in oracle if r["gemma_assessment"]["recommendation"] == "BLOCK") if oracle else 0
    risk = corr["correlation_results"]["risk_to_defi"] if corr else "UNKNOWN"

    print(f"\n[ SYSTEM STATUS ]\n")
    print(f"  Indicators in registry : {total_indicators}")
    print(f"  Oracle queries run     : {total_queries}")
    print(f"  Threats blocked        : {blocked}")
    print(f"  Current risk level     : {risk}")
    print(f"  Gemma 4 model          : google/gemma-3-27b-it")
    print(f"  Contract               : ThreatRegistry.sol (Sepolia testnet)")

def run_dashboard():
    clear()
    base = "/home/james-warren/Projects/Vektasafe Projects/octio"

    registry = load_json(f"{base}/registry.json")
    oracle = load_json(f"{base}/oracle_results.json")
    corr = load_json(f"{base}/correlation.json")

    print_header()
    print_stats(registry, oracle, corr)
    print_indicators(registry)
    print_oracle_results(oracle)
    print_correlation(corr)
    print_recommended_actions(corr)

    print("\n" + "=" * 70)
    print("  OCTIO -- github.com/vektasafe -- vektasafe.github.io")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    run_dashboard()
