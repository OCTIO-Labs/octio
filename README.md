# OCTIO -- On-Chain Threat Intelligence Oracle

A decentralised framework bridging Web2 attack surface monitoring with Web3 infrastructure security. Powered by Gemma 4.

**Author:** James Kabingu -- Vektasafe
**GitHub:** github.com/vektasafe/octio
**Portfolio:** vektasafe.github.io
**Licence:** MIT

---

## Overview

80% of funds stolen from Web3 projects originate from Web2 infrastructure attacks -- phishing, DNS hijacking, supply chain compromise, and cloud misconfiguration. OCTIO monitors these attack vectors in real time, analyses them using Gemma 4, and stores verified threat intelligence on-chain for DeFi protocols to query before executing sensitive operations.

---

## How OCTIO Differs from Existing Oracle Solutions

Existing oracle networks such as Chainlink, API3, Band Protocol, and UMA solve the general oracle problem -- bringing arbitrary off-chain data on-chain. OCTIO is not a general oracle. It is a security-specific intelligence primitive that existing solutions do not address.

| Limitation | Existing Oracles | OCTIO |
|------------|-----------------|-------|
| Domain | Price feeds, weather, sports, general data | Web2 attack surface indicators exclusively |
| Intelligence layer | Data relay -- no analysis | Gemma 4 classifies, reasons, and assesses each indicator |
| Threat context | None | Correlates current indicators against documented real-world incidents |
| Unknown threats | Cannot detect what is not in a feed | Gemma 4 flags suspicious domains not yet in any registry |
| Security focus | Not designed for security primitives | Built specifically for DeFi protocol security at runtime |
| Incident correlation | None | Maps current threat patterns to historical attacks with loss quantification |
| Campaign detection | None | Identifies coordinated attack patterns across multiple indicators |

### The core distinction

Chainlink and similar networks relay data -- they move a number or a string from off-chain to on-chain reliably. OCTIO reasons about data. When a new phishing URL enters the monitoring layer, Gemma 4 does not just store it -- it identifies the impersonation target, assesses severity, explains its reasoning, and determines whether the domain pattern matches known attack campaigns even if the specific URL has never been seen before.

This is the difference between a data feed and an intelligence layer.

### Limitations OCTIO directly addresses

**1. No existing oracle monitors Web2 attack vectors for Web3**
Chainlink has no phishing feed adapter. API3 has no DNS hijack monitor. The entire category of Web2 threat intelligence for Web3 protocols is unserved by existing oracle infrastructure.

**2. Existing solutions cannot catch unknown threats**
Rule-based systems and standard oracle feeds only flag known bad actors. OCTIO's Gemma 4 layer identified `metamask-security-alert.com` as suspicious from domain pattern alone -- before it appeared in any threat feed. No existing oracle network does this.

**3. No oracle provides incident correlation**
When a DeFi protocol queries Chainlink, it gets a data point. When it queries OCTIO, it gets a threat assessment correlated against $642 million in documented historical losses from similar attack patterns. That context is what protocol teams actually need.

---

## Components

- `monitor.py` -- Live phishing feed monitoring with Gemma 4 threat classification
- `registry.py` -- On-chain registry simulation with keccak256 hash storage
- `oracle.py` -- DeFi protocol query interface with Gemma 4 risk assessment
- `correlation.py` -- Incident correlation against documented real-world hacks
- `dashboard.py` -- Terminal dashboard for live threat visibility
- `contracts/ThreatRegistry.sol` -- Solidity contract for Sepolia testnet deployment

---

## Quick Start

```bash
pip install requests python-dotenv eth-hash[pycryptodome]
cp .env.example .env
# Add your OpenRouter API key to .env
python3 monitor.py
python3 registry.py
python3 oracle.py
python3 correlation.py
python3 dashboard.py
```

---

## Architecture

OCTIO operates as a four-layer system:

| Layer | Function | Technology |
|-------|----------|------------|
| L1: Monitoring | Scans public Web2 sources for threat indicators | Python, OpenPhish, Certstream |
| L2: Registry | Stores and governs verified threat intelligence | Solidity, Ethereum / Arbitrum |
| L3: Oracle Interface | Exposes threat data to querying protocols | Chainlink adapter, Solidity |
| L4: Dashboard | Public interface for intelligence visibility | Python terminal dashboard |

---

## Research

Built as a 4th year Computer Science research project at Kenyatta University.
Full whitepaper and research proposal available in the project documentation folder.

---

## Known Limitations and Roadmap

- Registry simulation in Python -- live contract at 0xb0F4ae6f47eE001804d933dc8AD4b34969C91A69 on Sepolia
- Web3.py bridge for on-chain submission in progress
- Additional monitoring sources (Certstream, PassiveDNS, npm audit) planned
- ReputationManager.sol, ValidationPool.sol, GovernanceController.sol in progress
- Model string is google/gemma-3-27b-it -- will update to Gemma 4 when available via OpenRouter
