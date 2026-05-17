import json
import hashlib
from datetime import datetime

class ThreatRegistry:
    def __init__(self):
        self.indicators = {}
        self.query_log = []

    def submit_indicator(self, url, analysis):
        target_hash = hashlib.sha256(
            url.split("/")[2].encode() if len(url.split("/")) > 2 else url.encode()
        ).hexdigest()[:16]

        indicator = {
            "id": len(self.indicators) + 1,
            "target_hash": target_hash,
            "url": url,
            "indicator_type": analysis["threat_type"],
            "severity": analysis["severity"],
            "target": analysis["target"],
            "reasoning": analysis["reasoning"],
            "timestamp": datetime.now().isoformat(),
            "status": "VALIDATED"
        }

        self.indicators[target_hash] = indicator
        print(f"  Submitted indicator #{indicator['id']} -- {target_hash}")
        return indicator

    def is_flagged(self, url):
        target_hash = hashlib.sha256(
            url.split("/")[2].encode() if len(url.split("/")) > 2 else url.encode()
        ).hexdigest()[:16]

        self.query_log.append({
            "query": url,
            "target_hash": target_hash,
            "timestamp": datetime.now().isoformat()
        })

        if target_hash in self.indicators:
            ind = self.indicators[target_hash]
            return True, ind["severity"], ind["indicator_type"]
        return False, None, None

    def get_all(self):
        return list(self.indicators.values())

    def save(self, path):
        with open(path, "w") as f:
            json.dump({
                "indicators": self.indicators,
                "query_log": self.query_log,
                "total_indicators": len(self.indicators),
                "total_queries": len(self.query_log)
            }, f, indent=2)
        print(f"Registry saved to {path}")

def load_and_register():
    registry = ThreatRegistry()

    with open("/home/james-warren/Projects/Vektasafe Projects/octio/indicators.json") as f:
        indicators = json.load(f)

    print("\n=== OCTIO On-Chain Registry (Simulation) ===")
    print("Submitting validated indicators...\n")

    for item in indicators:
        if item["gemma_analysis"]["is_threat"]:
            registry.submit_indicator(item["url"], item["gemma_analysis"])

    print(f"\nRegistry contains {len(registry.get_all())} validated indicators")

    print("\n=== Protocol Query Test ===")
    test_queries = [
        "http://www.dpdlocoqu.cyou/com",
        "https://uniswap.org",
        "http://metamask-security-alert.com/connect"
    ]

    for url in test_queries:
        flagged, severity, threat_type = registry.is_flagged(url)
        if flagged:
            print(f"FLAGGED: {url}")
            print(f"  Severity: {severity} | Type: {threat_type}")
        else:
            print(f"CLEAN: {url}")

    registry.save("/home/james-warren/Projects/Vektasafe Projects/octio/registry.json")
    return registry

if __name__ == "__main__":
    load_and_register()
