# OCTIO -- On-Chain Threat Intelligence Oracle

A decentralised framework bridging Web2 attack surface monitoring with Web3 infrastructure security. Powered by Gemma 4.

**Author:** James Kabingu -- [OCTIO-Labs](https://github.com/OCTIO-Labs) | [Vektasafe](https://github.com/vektasafe)
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
- `web3_bridge.py` -- Submits validated indicators directly to the live Sepolia contract
- `dns_monitor.py` -- VirusTotal DNS enrichment layer, dual-source confidence scoring (Gemma 4 + VirusTotal)
- `reputation.py` -- Cumulative domain reputation engine, threat scoring over time with CONFIRMED_THREAT classification
- `profiles.py` -- Protocol-specific risk profiles, groups threats by impersonated platform with CRITICAL/HIGH risk ratings
- `prediction.py` -- Gemma 4 predictive threat intelligence, forward-looking campaign analysis and next-target prediction
- `registry.py` -- Local registry cache with keccak256 hash storage
- `oracle.py` -- DeFi protocol query interface with Gemma 4 risk assessment
- `correlation.py` -- Incident correlation against documented real-world hacks
- `dashboard.py` -- Terminal dashboard for live threat visibility
- `contracts/ThreatRegistry.sol` -- Deployed and verified on Sepolia at `0xb0F4ae6f47eE001804d933dc8AD4b34969C91A69`

---

## Quick Start

### 1. Install dependencies

```bash
pip install requests python-dotenv eth-hash[pycryptodome] web3
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and add:
OPENROUTER_API_KEY="your_openrouter_key"
PRIVATE_KEY="your_wallet_private_key"
CONTRACT_ADDRESS="0xb0F4ae6f47eE001804d933dc8AD4b34969C91A69"
> Your wallet must be authorised as a submitter on the contract. The deployer address is already authorised. If you are running with a different wallet, contact the project maintainer to be added.

### 3. Run the full pipeline

```bash
# Step 1: Fetch live phishing URLs and classify with Gemma 4
python3 monitor.py

# Step 2: Enrich indicators with VirusTotal DNS data
python3 dns_monitor.py

# Step 3: Score domain reputation over time
python3 reputation.py

# Step 4: Build protocol-specific risk profiles
python3 profiles.py

# Step 5: Run predictive threat intelligence
python3 prediction.py

# Step 6: Submit verified indicators to the live Sepolia contract
python3 web3_bridge.py

# Step 7: Run the DeFi protocol query interface
python3 oracle.py

# Step 8: Correlate against documented real-world incidents
python3 correlation.py

# Step 9: View the live terminal dashboard
python3 dashboard.py
```

`monitor.py` writes to `indicators.json`. `web3_bridge.py` reads from `indicators.json` and submits confirmed threats on-chain. Run them in order.

---

## Live Contract

**ThreatRegistry on Sepolia testnet:**
`0xb0F4ae6f47eE001804d933dc8AD4b34969C91A69`

- Verified on Sourcify (exact match)
- View on Etherscan: https://sepolia.etherscan.io/address/0xb0F4ae6f47eE001804d933dc8AD4b34969C91A69
- 5 indicators submitted on-chain as of May 19, 2026

---

## Architecture

OCTIO operates as a four-layer system:

| Layer | Function | Technology |
|-------|----------|------------|
| L1: Monitoring | Scans public Web2 sources for threat indicators | Python, OpenPhish |
| L2: Registry | Stores verified threat intelligence on-chain | Solidity, Sepolia testnet |
| L3: Oracle Interface | Exposes threat data to querying protocols | Python, web3.py |
| L4: Dashboard | Public interface for intelligence visibility | Python terminal dashboard |

---

## Research

Built as a 4th year Computer Science research project at Kenyatta University.
Full whitepaper and research proposal available in the project documentation folder.

---

## Known Limitations and Roadmap

- Primary monitoring source is OpenPhish -- VirusTotal DNS enrichment and cumulative reputation scoring added. Certstream and npm audit feeds planned
- Submitter authorisation is manual -- governance layer (ValidationPool.sol) in progress
- No Chainlink adapter yet -- oracle query from other contracts requires external adapter
- ReputationManager.sol, GovernanceController.sol in progress
- Model string is google/gemma-3-27b-it via OpenRouter


NOTICE: TO BE MADE PRIVATE ON JUNE 18TH AT MIDNIGHT!!!!
