# OCTIO -- On-Chain Threat Intelligence Oracle

A decentralised framework bridging Web2 attack surface monitoring with Web3 infrastructure security. Powered by Gemma 4.

## Overview

80% of funds stolen from Web3 projects originate from Web2 infrastructure attacks -- phishing, DNS hijacking, supply chain compromise, and cloud misconfiguration. OCTIO monitors these attack vectors in real time, analyses them using Gemma 4, and stores verified threat intelligence on-chain for DeFi protocols to query before executing sensitive operations.

## Components

- `monitor.py` -- Live phishing feed monitoring with Gemma 4 threat classification
- `registry.py` -- On-chain registry simulation with keccak256 hash storage
- `oracle.py` -- DeFi protocol query interface with Gemma 4 risk assessment
- `correlation.py` -- Incident correlation against documented real-world hacks
- `dashboard.py` -- Terminal dashboard for live threat visibility
- `contracts/ThreatRegistry.sol` -- Solidity contract deployed on Sepolia testnet

## Quick Start

```bash
pip install requests python-dotenv
cp .env.example .env
# Add your OpenRouter API key to .env
python3 monitor.py
python3 registry.py
python3 oracle.py
python3 dashboard.py
```

## Research

Built as a 4th year Computer Science research project at Kenyatta University.
Full whitepaper and research proposal available in the project documentation.

## Author

James Kabingu -- github.com/James-Kabingu
