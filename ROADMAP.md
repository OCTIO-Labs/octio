# OCTIO -- Architecture and Roadmap

**Author:** James Kabingu -- OCTIO-Labs | Vektasafe
**Status:** Living document -- updated as the system evolves

---

## Current Architecture (Phase 1 -- Prototype)

OCTIO currently operates as a 9-step sequential pipeline:
Data is stored in flat JSON files. A single authorised wallet submits indicators to the live ThreatRegistry.sol contract on Sepolia.

---

## How Enterprise Oracles Automate

Standard enterprise oracles (Chainlink, Forta, Band Protocol) do not rely on manual scripts. They are fully automated data pipelines with monitoring, redundancy, and governance.

### Typical Enterprise Oracle Flow

**Layer 1 -- Data Ingestion**
Multiple feeds pulled automatically from APIs, webhooks, and data vendors. Ingestion is scheduled or event-driven, not manual.

**Layer 2 -- Normalisation and ETL**
Raw data transformed into a canonical schema. Invalid or malformed records rejected. Metadata (timestamp, source, confidence, proof) attached automatically.

**Layer 3 -- Validation and Aggregation**
Multiple independent nodes verify the same data. Aggregation logic produces a single oracle answer via median, weighted consensus, or outlier rejection.

**Layer 4 -- Proof Generation**
Cryptographic signatures or Merkle proofs created. Oracle response is tamper-evident and auditable.

**Layer 5 -- On-Chain Delivery**
Smart contract receives the oracle update, stores the value, emits events. Consumer contracts query synchronously or asynchronously.

**Layer 6 -- Health and SLA Automation**
Node status, feed freshness, and response latency monitored. Alerting triggers on failures, stale data, or misbehaviour. Failover automatically switches to backup providers.

**Layer 7 -- Governance and Access Control**
New data sources and nodes added through governance or permissions. Audit trails and access logs maintained.

### How Standard Oracles Detect Threats in Parallel

For security-related data, enterprise systems separate detection from the oracle layer:

- Threat intelligence platform ingests feeds in parallel
- Detection engines classify and score each indicator
- Multiple jobs or nodes run concurrently for coverage
- The oracle layer delivers the resulting threat score on-chain

The key pattern: **multi-source parallel ingestion → distributed consensus → independent validation → automated failover**

---

## OCTIO vs Enterprise Oracles -- Gap Analysis

| Capability | Enterprise Standard | OCTIO Current |
|------------|-------------------|---------------|
| Data ingestion | Multi-source parallel | OpenPhish only (sequential) |
| Intelligence layer | Data relay, no reasoning | Gemma 4 classifies, reasons, predicts |
| Validation | Multi-node consensus | Single LLM + VirusTotal |
| Submission | Automated daemon | Manual web3_bridge.py |
| Storage | Database / event store | Flat JSON files |
| Monitoring | Health checks, alerts, SLA | Terminal dashboard |
| Query interface | AggregatorV3Interface (Chainlink standard) | Custom ABI |
| Dispute mechanism | Dispute windows, slashing | Contract enums unused |
| Incentive model | Token staking (FORT, LINK) | None |
| Process management | systemd / Docker Compose | Manual execution |

**What OCTIO has that no enterprise oracle has:**
- Web2 signal ingestion (phishing URLs, DNS enrichment)
- LLM reasoning layer that classifies unknown threats by pattern
- Predictive campaign forecasting
- Incident correlation against documented real-world losses
- On-chain registry with native isFlagged() callable by Solidity contracts

---

## Roadmap

### Phase 2 -- Automated Pipeline

Convert the 9-step manual process into a scheduled daemon.

**pipeline.py with APScheduler:**
```python
from apscheduler.schedulers.blocking import BlockingScheduler
from monitor import run_monitor
from dns_monitor import enrich_indicators
from reputation import update_reputation
from profiles import build_profiles
from web3_bridge import run_bridge

def run_cycle():
    run_monitor()
    enrich_indicators()
    update_reputation()
    build_profiles()
    run_bridge()

scheduler = BlockingScheduler()
scheduler.add_job(run_cycle, 'interval', minutes=15)
scheduler.add_job(run_prediction_and_correlation, 'interval', hours=1)
scheduler.start()
```

**systemd unit for process management:**
```ini
[Unit]
Description=OCTIO Threat Intelligence Daemon
After=network.target

[Service]
Type=simple
User=james-warren
WorkingDirectory=/home/james-warren/Projects/Vektasafe Projects/octio
ExecStart=/usr/bin/python3 pipeline.py
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Priority fixes:**
- Replace hardcoded paths with pathlib.Path(__file__).parent
- Add disputeIndicator() and rejectIndicator() to ThreatRegistry.sol
- Use VirusTotal verdict as a validation gate, not just metadata
- Replace time.sleep(15) in dns_monitor.py with async rate limiting

### Phase 3 -- Enterprise Architecture

Convert to a fully async event-driven daemon matching Forta and Chainlink architecture.

**Async worker architecture:**
**On-chain feedback loop (unique to OCTIO):**
When a DeFi protocol queries a domain not in the registry, the daemon immediately prioritises investigating that domain. This closes the loop between on-chain queries and off-chain monitoring -- something no existing oracle has for security intelligence.

```python
async def onchain_listener(w3, contract):
    event_filter = contract.events.QueryExecuted.create_filter(from_block='latest')
    while True:
        for event in event_filter.get_new_entries():
            if not event['args']['flagged']:
                await priority_queue.put(event['args']['targetHash'])
        await asyncio.sleep(12)
```

**Storage migration:**
Replace flat JSON files with SQLite (local) or PostgreSQL (production). Keep raw evidence, feed source, confidence scores, and model output. Store pipeline state and retry metadata.

### Phase 4 -- Ecosystem Integration

- Chainlink external adapter -- makes OCTIO queryable via AggregatorV3Interface from any contract
- ValidationPool.sol -- multi-party validation where registered researchers vote on indicators
- ReputationManager.sol -- on-chain reputation scoring
- GovernanceController.sol -- decentralised governance for new data sources and submitters
- FORT-style staking model -- economic incentives for external contributors

---

## The Unique OCTIO Differentiator

Every enterprise oracle monitors the blockchain. OCTIO monitors the infrastructure that serves the blockchain's users.

The feedback loop in Phase 3 is the architectural feature that no existing oracle has: when a DeFi protocol queries OCTIO about an unknown domain, the system automatically investigates it. The oracle learns from its own query traffic. That is the long-term moat.

---

## References

- Chainlink node architecture -- docs.chain.link
- Forta Network scan node documentation -- docs.forta.network
- Band Protocol yoda process -- docs.bandchain.org
- APScheduler documentation -- apscheduler.readthedocs.io
- asyncio queue documentation -- docs.python.org/3/library/asyncio-queue.html
