#!/usr/bin/env python3
import json, os, pathlib
from datetime import datetime, timezone
from dotenv import load_dotenv
from eth_hash.auto import keccak
from web3 import Web3

BASE = pathlib.Path('/home/james-warren/Projects/Vektasafe Projects/octio')
load_dotenv(BASE / '.env')

RPC_URL          = 'https://ethereum-sepolia-rpc.publicnode.com'
CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS').strip('"')
PRIVATE_KEY      = os.getenv('PRIVATE_KEY').strip('"')

INDICATOR_TYPE = {'PHISHING':0,'MALWARE':1,'SCAM':2,'DNS_HIJACK':3,'SUPPLY_CHAIN':4,'BGP_ANOMALY':5}
SEVERITY       = {'LOW':0,'MEDIUM':1,'HIGH':2,'CRITICAL':3}

ABI = [
    {'name':'submitIndicator','type':'function','stateMutability':'nonpayable',
     'inputs':[{'name':'targetHash','type':'bytes32'},{'name':'indicatorType','type':'uint8'},{'name':'severity','type':'uint8'},{'name':'evidenceHash','type':'bytes32'},{'name':'reasoning','type':'string'}],
     'outputs':[{'name':'','type':'uint256'}]},
    {'name':'getTotalIndicators','type':'function','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'uint256'}]},
    {'name':'isFlagged','type':'function','stateMutability':'view',
     'inputs':[{'name':'targetHash','type':'bytes32'}],
     'outputs':[{'name':'flagged','type':'bool'},{'name':'severity','type':'uint8'},{'name':'count','type':'uint256'}]}
]

def connect():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise ConnectionError('Cannot connect to Sepolia')
    print('Connected to Sepolia  |  block ' + str(w3.eth.block_number))
    return w3

def load_indicators():
    with open(BASE / 'indicators.json') as f:
        data = json.load(f)

    rep_path = BASE / 'reputation.json'
    if rep_path.exists():
        with open(rep_path) as f:
            reputation = json.load(f)
        qualified = {'CONFIRMED_THREAT', 'HIGH_RISK'}
        def domain_from(url):
            parts = url.split('/')
            return parts[2] if len(parts) > 2 else url
        threats = [i for i in data
                   if i.get('gemma_analysis', {}).get('is_threat')
                   and reputation.get(domain_from(i['url']), {}).get('label') in qualified]
        print('Loaded ' + str(len(data)) + ' indicators  |  ' + str(len(threats)) + ' qualified for submission (CONFIRMED_THREAT or HIGH_RISK)')
    else:
        threats = [i for i in data if i.get('gemma_analysis', {}).get('is_threat')]
        print('Loaded ' + str(len(data)) + ' indicators  |  ' + str(len(threats)) + ' confirmed threats')
    return threats

def to_bytes32(hex_str):
    return bytes.fromhex(hex_str.ljust(64, '0')[:64])

def make_evidence_hash(url):
    return keccak(url.encode())

def submit_indicator(w3, contract, account, indicator, nonce=None):
    analysis  = indicator['gemma_analysis']
    url       = indicator['url']
    target_bytes   = to_bytes32(indicator['target_hash'])
    evidence_bytes = make_evidence_hash(url)
    ind_type  = INDICATOR_TYPE.get(analysis['threat_type'], 0)
    severity  = SEVERITY.get(analysis['severity'], 0)
    reasoning = analysis['reasoning']
    print('  Submitting: ' + url)
    print('  Type: ' + analysis['threat_type'] + '  Severity: ' + analysis['severity'])
    if nonce is None:
        nonce = w3.eth.get_transaction_count(account.address, 'pending')
    gas_price = int(w3.eth.gas_price * 1.2)
    tx = contract.functions.submitIndicator(
        target_bytes, ind_type, severity, evidence_bytes, reasoning
    ).build_transaction({'from':account.address,'nonce':nonce,'gasPrice':gas_price,'gas':500000})
    signed  = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print('  TX sent: 0x' + tx_hash.hex())
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    status  = 'SUCCESS' if receipt.status == 1 else 'FAILED'
    print('  Status: ' + status + '  block ' + str(receipt.blockNumber) + '  gas ' + str(receipt.gasUsed))
    return {'url':url,'tx_hash':'0x'+tx_hash.hex(),'block':receipt.blockNumber,'gas_used':receipt.gasUsed,'status':status,'timestamp':datetime.now(timezone.utc).isoformat()}

def run_bridge():
    print('=== OCTIO Web3 Bridge ===')
    print('Contract: ' + CONTRACT_ADDRESS)
    w3       = connect()
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)
    account  = w3.eth.account.from_key(PRIVATE_KEY)
    print('Submitter: ' + account.address)
    total_before = contract.functions.getTotalIndicators().call()
    print('Indicators on-chain before: ' + str(total_before))
    indicators = load_indicators()
    if not indicators:
        print('No confirmed threats. Run monitor.py first.')
        return
    results = []
    nonce = w3.eth.get_transaction_count(account.address, 'pending')
    for indicator in indicators:
        try:
            results.append(submit_indicator(w3, contract, account, indicator, nonce))
            nonce += 1
        except Exception as e:
            print('  ERROR: ' + str(e))
            nonce += 1
    total_after = contract.functions.getTotalIndicators().call()
    print('On-chain after: ' + str(total_after) + '  Submitted: ' + str(total_after - total_before))
    with open(BASE / 'bridge_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    success = sum(1 for r in results if r['status'] == 'SUCCESS')
    print('=== Bridge complete: ' + str(success) + '/' + str(len(results)) + ' successful ===')
    print('https://sepolia.etherscan.io/address/' + CONTRACT_ADDRESS)

if __name__ == '__main__':
    run_bridge()