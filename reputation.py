import json
import pathlib
from datetime import datetime, timezone

BASE = pathlib.Path("/home/james-warren/Projects/Vektasafe Projects/octio")

SEVERITY_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONFIDENCE_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

def extract_domain(url):
    parts = url.split("/")
    return parts[2] if len(parts) > 2 else url

def load_reputation():
    path = BASE / "reputation.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}

def save_reputation(reputation):
    with open(BASE / "reputation.json", "w") as f:
        json.dump(reputation, f, indent=2)

def calculate_score(record):
    times_flagged = record["times_flagged"]
    avg_vt = record["total_vt_malicious"] / times_flagged if times_flagged > 0 else 0
    severity = SEVERITY_SCORE.get(record["highest_severity"], 1)
    confidence = CONFIDENCE_SCORE.get(record["highest_confidence"], 1)
    score = (times_flagged * 10) + (avg_vt * 2) + (severity * 5) + (confidence * 5)
    if times_flagged >= 3:
        score *= 1.5
    if times_flagged >= 5:
        score *= 2.0
    return round(score, 2)

def get_reputation_label(score):
    if score >= 80:
        return "CONFIRMED_THREAT"
    elif score >= 50:
        return "HIGH_RISK"
    elif score >= 25:
        return "SUSPICIOUS"
    elif score >= 10:
        return "WATCH"
    else:
        return "LOW_RISK"

def update_reputation():
    indicators_path = BASE / "indicators.json"
    if not indicators_path.exists():
        print("No indicators.json found. Run monitor.py first.")
        return

    with open(indicators_path) as f:
        indicators = json.load(f)

    reputation = load_reputation()
    now = datetime.now(timezone.utc).isoformat()

    print("\n=== OCTIO Reputation Engine ===")
    print(f"Timestamp: {now}")
    print(f"Processing {len(indicators)} indicators...\n")

    for indicator in indicators:
        if not indicator.get("gemma_analysis", {}).get("is_threat"):
            continue

        url = indicator["url"]
        domain = extract_domain(url)
        analysis = indicator["gemma_analysis"]
        vt = indicator.get("virustotal", {})
        confidence = indicator.get("confidence", "LOW")
        severity = analysis.get("severity", "LOW")
        vt_malicious = vt.get("malicious", 0)

        if domain not in reputation:
            reputation[domain] = {
                "domain": domain,
                "first_seen": now,
                "last_seen": now,
                "times_flagged": 0,
                "total_vt_malicious": 0,
                "highest_severity": "LOW",
                "highest_confidence": "LOW",
                "threat_types": [],
                "urls_seen": [],
                "score": 0,
                "label": "LOW_RISK"
            }

        record = reputation[domain]
        record["times_flagged"] += 1
        record["last_seen"] = now
        record["total_vt_malicious"] += vt_malicious

        if SEVERITY_SCORE.get(severity, 0) > SEVERITY_SCORE.get(record["highest_severity"], 0):
            record["highest_severity"] = severity

        if CONFIDENCE_SCORE.get(confidence, 0) > CONFIDENCE_SCORE.get(record["highest_confidence"], 0):
            record["highest_confidence"] = confidence

        threat_type = analysis.get("threat_type", "UNKNOWN")
        if threat_type not in record["threat_types"]:
            record["threat_types"].append(threat_type)

        if url not in record["urls_seen"]:
            record["urls_seen"].append(url)

        record["score"] = calculate_score(record)
        record["label"] = get_reputation_label(record["score"])

    save_reputation(reputation)

    print("Domain Reputation Report:")
    print("-" * 80)
    sorted_domains = sorted(reputation.values(), key=lambda x: x["score"], reverse=True)
    for record in sorted_domains:
        print(f"Domain:    {record['domain']}")
        print(f"Score:     {record['score']} -- {record['label']}")
        print(f"Flagged:   {record['times_flagged']} time(s)")
        print(f"Severity:  {record['highest_severity']} | Confidence: {record['highest_confidence']}")
        print(f"VT Total:  {record['total_vt_malicious']} malicious votes")
        print(f"First seen: {record['first_seen'][:10]} | Last seen: {record['last_seen'][:10]}")
        print()

    confirmed = sum(1 for r in reputation.values() if r["label"] == "CONFIRMED_THREAT")
    high_risk = sum(1 for r in reputation.values() if r["label"] == "HIGH_RISK")
    suspicious = sum(1 for r in reputation.values() if r["label"] == "SUSPICIOUS")

    print("-" * 80)
    print(f"Total domains tracked: {len(reputation)}")
    print(f"CONFIRMED_THREAT: {confirmed}")
    print(f"HIGH_RISK:        {high_risk}")
    print(f"SUSPICIOUS:       {suspicious}")

    return reputation

if __name__ == "__main__":
    update_reputation()
