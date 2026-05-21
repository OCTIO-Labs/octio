import json
import pathlib
from datetime import datetime, timezone

BASE = pathlib.Path("/home/james-warren/Projects/Vektasafe Projects/octio")

def clear():
    import os
    os.system("clear")

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None

def divider():
    print("-" * 70)

def header():
    print("=" * 70)
    print("  OCTIO -- On-Chain Threat Intelligence Oracle")
    print("  Powered by Gemma 4 (google/gemma-3-27b-it) via OpenRouter")
    print("  " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + " UTC")
    print("=" * 70)

def section(title):
    print()
    print("  [ " + title + " ]")
    divider()

def print_system_status(reputation, profiles, prediction, bridge):
    section("SYSTEM STATUS")
    rep_count = len(reputation) if reputation else 0
    confirmed = sum(1 for r in reputation.values() if r.get("label") == "CONFIRMED_THREAT") if reputation else 0
    high_risk = sum(1 for r in reputation.values() if r.get("label") == "HIGH_RISK") if reputation else 0
    prof_count = len(profiles) if profiles else 0
    critical_profs = sum(1 for p in profiles.values() if p.get("risk_rating") == "CRITICAL") if profiles else 0
    threat_level = prediction["prediction"]["threat_level"] if prediction else "UNKNOWN"
    on_chain = bridge[-1]["block"] if bridge else "N/A"

    print("  Domains tracked        : " + str(rep_count))
    print("  CONFIRMED_THREAT       : " + str(confirmed))
    print("  HIGH_RISK              : " + str(high_risk))
    print("  Protocols profiled     : " + str(prof_count))
    print("  CRITICAL protocols     : " + str(critical_profs))
    print("  Current threat level   : " + threat_level)
    print("  Last on-chain block    : " + str(on_chain))
    print("  Contract               : 0xb0F4ae6f47eE001804d933dc8AD4b34969C91A69")
    print("  Network                : Sepolia testnet")

def print_reputation(reputation):
    if not reputation:
        print("  No reputation data found.")
        return
    section("DOMAIN REPUTATION -- TOP THREATS")
    sorted_domains = sorted(reputation.values(), key=lambda x: x["score"], reverse=True)[:8]
    print("  " + "DOMAIN".ljust(35) + "SCORE".ljust(10) + "LABEL".ljust(20) + "FLAGGED")
    divider()
    for r in sorted_domains:
        domain = r["domain"][:33].ljust(35)
        score = str(r["score"]).ljust(10)
        label = r["label"].ljust(20)
        flagged = str(r["times_flagged"]) + "x"
        print("  " + domain + score + label + flagged)

def print_profiles(profiles):
    if not profiles:
        print("  No profile data found.")
        return
    section("PROTOCOL RISK PROFILES")
    sorted_profiles = sorted(profiles.values(), key=lambda x: x["max_reputation_score"], reverse=True)
    print("  " + "PROTOCOL".ljust(25) + "RISK".ljust(12) + "THREATS".ljust(10) + "CONFIRMED")
    divider()
    for p in sorted_profiles:
        protocol = p["protocol"][:23].ljust(25)
        risk = p["risk_rating"].ljust(12)
        total = str(p["total_threats"]).ljust(10)
        confirmed = str(p["confirmed_threats"])
        print("  " + protocol + risk + total + confirmed)

def print_prediction(prediction):
    if not prediction:
        print("  No prediction data found.")
        return
    section("PREDICTIVE THREAT INTELLIGENCE")
    pred = prediction["prediction"]
    print("  Threat Level: " + pred["threat_level"])
    print()
    print("  Escalating Campaigns:")
    for c in pred.get("escalating_campaigns", [])[:2]:
        print("    " + c["campaign"][:65])
        print("    Peak: " + c["peak_window"] + " | Confidence: " + c["confidence"])
        print()
    print("  Predicted Next Targets:")
    for t in pred.get("predicted_next_targets", [])[:3]:
        print("    " + t["target"] + " -- " + t["risk"])
    print()
    print("  Analyst Advisory:")
    advisory = pred.get("analyst_advisory", "")
    words = advisory.split()
    line = "    "
    for word in words:
        if len(line) + len(word) > 68:
            print(line)
            line = "    " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

def print_oracle(oracle):
    if not oracle:
        print("  No oracle data found.")
        return
    section("ORACLE QUERY RESULTS")
    for result in oracle:
        rec = result["gemma_assessment"]["recommendation"]
        risk = result["gemma_assessment"]["risk_level"]
        target = result["target"][:45]
        status = "BLOCK " if rec == "BLOCK" else "CAUTION" if rec == "CAUTION" else "PROCEED"
        print("  [" + status + "] [" + risk.ljust(10) + "] " + target)

def print_bridge(bridge):
    if not bridge:
        print("  No bridge data found.")
        return
    section("RECENT ON-CHAIN SUBMISSIONS")
    for r in bridge[-5:]:
        status = r.get("status", "UNKNOWN")
        block = str(r.get("block", "N/A"))
        url = r.get("url", "")[:45]
        print("  [" + status + "] block " + block + " -- " + url)

def print_actions(prediction):
    if not prediction:
        return
    section("RECOMMENDED ACTIONS -- NEXT 24 HOURS")
    for i, action in enumerate(prediction["prediction"].get("recommended_actions", [])[:4], 1):
        words = action.split()
        line = "  " + str(i) + ". "
        for word in words:
            if len(line) + len(word) > 68:
                print(line)
                line = "     " + word + " "
            else:
                line += word + " "
        if line.strip():
            print(line)

def run_dashboard():
    clear()
    reputation  = load_json(BASE / "reputation.json")
    profiles    = load_json(BASE / "profiles.json")
    prediction  = load_json(BASE / "prediction.json")
    oracle      = load_json(BASE / "oracle_results.json")
    bridge      = load_json(BASE / "bridge_results.json")

    header()
    print_system_status(reputation, profiles, prediction, bridge)
    print_reputation(reputation)
    print_profiles(profiles)
    print_prediction(prediction)
    print_oracle(oracle)
    print_bridge(bridge)
    print_actions(prediction)

    print()
    print("=" * 70)
    print("  OCTIO -- github.com/OCTIO-Labs/octio")
    print("  OCTIO-Labs | Vektasafe -- Nairobi, Kenya")
    print("=" * 70)
    print()

if __name__ == "__main__":
    run_dashboard()
