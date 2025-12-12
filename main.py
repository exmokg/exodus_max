#!/usr/bin/env python3

import sys
import json
import requests
from typing import Dict, List, Tuple, Optional
from time import sleep

try:
    from bip_utils import (
        Bip39MnemonicValidator, Bip39SeedGenerator, Bip44, 
        Bip44Coins, Bip44Changes
    )
except ImportError:
    print("Required libraries missing:")
    print("pip install bip-utils requests")
    sys.exit(1)


class WalletChecker:

    USDT_CONTRACTS = {
        'TRC20': 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
        'ETH': '0xdac17f958d2ee523a2206206994597c13d831ec7'
    }

    SUPPORTED_CHAINS = {
        'Bitcoin': {
            'coin': Bip44Coins.BITCOIN,
            'symbol': 'BTC',
            'decimals': 8,
            'api': 'blockchair',
            'explorer': 'https://blockchair.com/bitcoin/address/'
        },
        'Ethereum': {
            'coin': Bip44Coins.ETHEREUM,
            'symbol': 'ETH',
            'decimals': 18,
            'api': 'blockchair',
            'explorer': 'https://etherscan.io/address/',
            'supports_tokens': True
        },
        'Tron': {
            'coin': Bip44Coins.TRON,
            'symbol': 'TRX',
            'decimals': 6,
            'api': 'trongrid',
            'explorer': 'https://tronscan.org/#/address/',
            'supports_tokens': True
        },
        'Litecoin': {
            'coin': Bip44Coins.LITECOIN,
            'symbol': 'LTC',
            'decimals': 8,
            'api': 'blockchair',
            'explorer': 'https://blockchair.com/litecoin/address/'
        },
        'Dogecoin': {
            'coin': Bip44Coins.DOGECOIN,
            'symbol': 'DOGE',
            'decimals': 8,
            'api': 'blockchair',
            'explorer': 'https://blockchair.com/dogecoin/address/'
        },
        'Bitcoin Cash': {
            'coin': Bip44Coins.BITCOIN_CASH,
            'symbol': 'BCH',
            'decimals': 8,
            'api': 'blockchair',
            'explorer': 'https://blockchair.com/bitcoin-cash/address/'
        }
    }

    def __init__(self, mnemonic: str):
        self.mnemonic = mnemonic.strip()
        self.wallets = {}

    def validate_mnemonic(self) -> bool:
        try:
            return Bip39MnemonicValidator().IsValid(self.mnemonic)
        except Exception as e:
            print(f"Validation error: {e}")
            return False

    def derive_addresses(self, chain_name: str, num_addresses: int = 5) -> List[str]:
        chain_config = self.SUPPORTED_CHAINS.get(chain_name)
        if not chain_config:
            return []

        addresses = []

        try:
            seed_bytes = Bip39SeedGenerator(self.mnemonic).Generate()
            bip44_mst = Bip44.FromSeed(seed_bytes, chain_config['coin'])
            bip44_acc = bip44_mst.Purpose().Coin().Account(0)
            bip44_chg = bip44_acc.Change(Bip44Changes.CHAIN_EXT)

            for i in range(num_addresses):
                bip44_addr = bip44_chg.AddressIndex(i)
                address = bip44_addr.PublicKey().ToAddress()
                addresses.append(address)

            self.wallets[chain_name] = addresses

        except Exception as e:
            print(f"Derivation error {chain_name}: {e}")

        return addresses

    def get_balance_blockchair(self, address: str, chain: str) -> Tuple[float, int]:
        chain_map = {
            'Bitcoin': 'bitcoin',
            'Ethereum': 'ethereum',
            'Litecoin': 'litecoin',
            'Dogecoin': 'dogecoin',
            'Bitcoin Cash': 'bitcoin-cash'
        }

        chain_id = chain_map.get(chain, chain.lower())
        url = f"https://api.blockchair.com/{chain_id}/dashboards/address/{address}"

        try:
            response = requests.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if 'data' in data and address in data['data']:
                    addr_data = data['data'][address]['address']
                    balance = addr_data.get('balance', 0)
                    tx_count = addr_data.get('transaction_count', 0)

                    decimals = self.SUPPORTED_CHAINS[chain]['decimals']
                    balance = balance / (10 ** decimals)

                    return balance, tx_count

            elif response.status_code == 429:
                sleep(2)
                return self.get_balance_blockchair(address, chain)

        except Exception as e:
            print(f"Request error {chain}: {e}")

        return 0.0, 0

    def get_tron_balance(self, address: str) -> Tuple[float, int, List[Dict]]:
        try:
            url = f"https://apilist.tronscanapi.com/api/account?address={address}"
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0'
            }

            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()

                trx_balance = 0.0
                if 'balance' in data:
                    trx_balance = data['balance'] / 1_000_000
                elif 'balances' in data and len(data['balances']) > 0:
                    for bal in data['balances']:
                        if bal.get('tokenId') == '_' or bal.get('tokenAbbr') == 'trx':
                            trx_balance = float(bal.get('amount', 0)) / 1_000_000
                            break

                trc20_tokens = []

                if 'trc20token_balances' in data and isinstance(data['trc20token_balances'], list):
                    for token in data['trc20token_balances']:
                        token_addr = token.get('tokenId', '')
                        token_symbol = token.get('tokenAbbr', 'UNKNOWN')
                        token_balance = float(token.get('balance', 0))
                        token_decimals = int(token.get('tokenDecimal', 6))

                        if token_balance > 0:
                            if token_addr == self.USDT_CONTRACTS['TRC20'] or token_symbol == 'USDT':
                                trc20_tokens.append({
                                    'symbol': 'USDT',
                                    'name': 'Tether USD (TRC20)',
                                    'balance': token_balance / (10 ** token_decimals),
                                    'contract': token_addr
                                })
                            else:
                                trc20_tokens.append({
                                    'symbol': token_symbol,
                                    'name': token.get('tokenName', token_symbol),
                                    'balance': token_balance / (10 ** token_decimals),
                                    'contract': token_addr
                                })

                return trx_balance, 0, trc20_tokens

            elif response.status_code == 429:
                print(f"TronScan rate limit - waiting 3 sec...")
                sleep(3)
                return self.get_tron_balance(address)

            return self._get_tron_balance_fallback(address)

        except Exception as e:
            print(f"Tron request error: {e}")
            return self._get_tron_balance_fallback(address)

    def _get_tron_balance_fallback(self, address: str) -> Tuple[float, int, List[Dict]]:
        try:
            url = "https://api.trongrid.io/wallet/getaccount"
            payload = {
                "address": address,
                "visible": True
            }
            headers = {
                'Content-Type': 'application/json',
                'TRON-PRO-API-KEY': ''
            }

            response = requests.post(url, json=payload, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()

                trx_balance = data.get('balance', 0) / 1_000_000

                trc20_tokens = []

                return trx_balance, 0, trc20_tokens

        except Exception as e:
            pass

        return 0.0, 0, []

    def get_eth_tokens(self, address: str) -> List[Dict]:
        url = f"https://api.blockchair.com/ethereum/dashboards/address/{address}?erc_20=true"

        try:
            response = requests.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if 'data' in data and address in data['data']:
                    tokens = data['data'][address].get('layer_2', {}).get('erc_20', [])

                    result = []
                    for token in tokens:
                        token_addr = token.get('token_address', '').lower()
                        balance = float(token.get('balance', 0))

                        if balance > 0:
                            if token_addr == self.USDT_CONTRACTS['ETH'].lower():
                                result.append({
                                    'symbol': 'USDT',
                                    'name': 'Tether USD (ERC20)',
                                    'balance': balance,
                                    'decimals': 6,
                                    'contract': token_addr
                                })
                            else:
                                result.append({
                                    'symbol': token.get('token_symbol', 'UNKNOWN'),
                                    'name': token.get('token_name', ''),
                                    'balance': balance,
                                    'decimals': int(token.get('token_decimals', 18)),
                                    'contract': token_addr
                                })

                    return result

        except Exception as e:
            print(f"ERC20 tokens error: {e}")

        return []

    def check_all_balances(self, num_addresses: int = 5):
        print(f"Checking {num_addresses} addresses per chain")
        print(f"Supported: BTC, ETH, TRX, LTC, DOGE, BCH + USDT (ERC20/TRC20)\n")

        total_value_found = False
        all_balances = {}
        usdt_total = {'ERC20': 0.0, 'TRC20': 0.0}

        for chain_name in self.SUPPORTED_CHAINS.keys():
            print(f"\n{'─'*70}")
            print(f"Chain: {chain_name} ({self.SUPPORTED_CHAINS[chain_name]['symbol']})")
            print(f"{'─'*70}")

            addresses = self.derive_addresses(chain_name, num_addresses)

            if not addresses:
                print("Failed to generate addresses")
                continue

            chain_has_balance = False
            chain_total = 0.0

            for idx, address in enumerate(addresses):
                if chain_name == 'Tron':
                    balance, tx_count, trc20_tokens = self.get_tron_balance(address)
                else:
                    balance, tx_count = self.get_balance_blockchair(address, chain_name)
                    trc20_tokens = []

                if balance > 0 or tx_count > 0 or trc20_tokens:
                    chain_has_balance = True
                    total_value_found = True
                    chain_total += balance

                    print(f"\n  Address #{idx}:")
                    print(f"     {address}")
                    print(f"     Balance: {balance:.8f} {self.SUPPORTED_CHAINS[chain_name]['symbol']}")

                    if tx_count > 0:
                        print(f"     Transactions: {tx_count}")

                    print(f"     Explorer: {self.SUPPORTED_CHAINS[chain_name]['explorer']}{address}")

                    if chain_name == 'Ethereum' and balance >= 0:
                        eth_tokens = self.get_eth_tokens(address)
                        if eth_tokens:
                            print(f"\n     ERC-20 Tokens:")
                            for token in eth_tokens:
                                token_balance = token['balance'] / (10 ** token['decimals'])
                                print(f"        • {token['symbol']}: {token_balance:.6f}")

                                if token['symbol'] == 'USDT':
                                    usdt_total['ERC20'] += token_balance

                    if chain_name == 'Tron' and trc20_tokens:
                        print(f"\n     TRC-20 Tokens:")
                        for token in trc20_tokens:
                            print(f"        • {token['symbol']}: {token['balance']:.6f}")

                            if token['symbol'] == 'USDT':
                                usdt_total['TRC20'] += token['balance']

                sleep(0.5)

            if chain_has_balance:
                all_balances[chain_name] = chain_total
            else:
                print(f"  No activity on first {num_addresses} addresses")

        print("\n" + "="*70)

        if not total_value_found:
            print("No assets found on checked addresses")
            print("Try increasing number of addresses to check")
        else:
            print("Заебись пачекал нахуй всё!\n")
            print("Ебанутся,итого:")
            print("─" * 70)

            for chain, balance in all_balances.items():
                symbol = self.SUPPORTED_CHAINS[chain]['symbol']
                print(f"   {chain:15} : {balance:.8f} {symbol}")

            print("\nUSDT BALANCE:")
            print("─" * 70)
            if usdt_total['ERC20'] > 0:
                print(f"   USDT (ERC20)    : {usdt_total['ERC20']:.6f} USDT")
            if usdt_total['TRC20'] > 0:
                print(f"   USDT (TRC20)    : {usdt_total['TRC20']:.6f} USDT")

            total_usdt = usdt_total['ERC20'] + usdt_total['TRC20']
            if total_usdt > 0:
                print(f"   {'─' * 30}")
                print(f"   TOTAL USDT      : {total_usdt:.6f} USDT")

        print("="*70 + "\n")


def validate_mnemonic_words(mnemonic: str) -> bool:
    words = mnemonic.strip().split()

    if len(words) != 12:
        print(f"Seed phrase must contain 12 words (got: {len(words)})")
        return False

    return True


def main():
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                                                               ║")
    print("║                    BigDig Max by Meow-Meow                    ║")
    print("║                                                               ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()
    print("Wallet balance checker using BIP39/BIP44 seed phrase")
    print("Supported networks:")
    print("  • Bitcoin (BTC), Ethereum (ETH), Tron (TRX)")
    print("  • Litecoin (LTC), Dogecoin (DOGE), Bitcoin Cash (BCH)")
    print("  • USDT (ERC20 on Ethereum + TRC20 on Tron)")
    print("\nWARNING: Never enter seed phrase on untrusted sites!")
    print("="*70 + "\n")

    mnemonic = input("Праток хуйника любую сид фразу (залупа такая из 12 слов): ").strip()

    if not validate_mnemonic_words(mnemonic):
        return

    checker = WalletChecker(mnemonic)

    print("\nЗалупирую Сид фразу...")
    if not checker.validate_mnemonic():
        print("Invalid seed phrase! Check word correctness.")
        return

    print("Заебись! Сид фраза валидна!\n")

    num_addresses = 5
    
    checker.check_all_balances(num_addresses)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nCritical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
