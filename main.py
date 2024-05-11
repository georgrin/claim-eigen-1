import requests
import socket
import socks
from web3 import Web3
from web3.exceptions import Web3Exception
from eth_account import Account
from eth_account.messages import encode_defunct
import random
import time
import json
from config import ETH_NODE_RPC, USE_PROXY, SLEEP_FROM, SLEEP_TO
from urllib.parse import urlparse
import traceback
import random

# Чтение приватных ключей из файла
def read_private_keys(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f]

# Чтение прокси из файла
def read_proxies(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f]

# Получение публичного IP (None, если прокси не работает)
def get_public_ip(proxy=None):
    try:
        response = make_request('GET', 'https://httpbin.org/ip', proxy=proxy, timeout=20)
        if response and not hasattr(response, 'error'):
            ip = json.loads(response.text)["origin"]
            return ip
        else:
            return None
    except:
        return None

# Подписание сообщения
def sign_message(private_key, message):
    w3 = Web3()
    signable_message = encode_defunct(text=message)
    signed_message = w3.eth.account.sign_message(signable_message, private_key=private_key)
    return signed_message.signature.hex()

# Логирование
def log(message):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f'[{timestamp}] {message}')

# Функция-прокладка для запросов
def make_request(method, url, proxy=None, user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36", **kwargs):
    headers = {}
    if user_agent:
        headers['User-Agent'] = user_agent

    if proxy:
        parsed_proxy = urlparse(proxy)
        socks.set_default_proxy(socks.SOCKS5, parsed_proxy.hostname, parsed_proxy.port, True, parsed_proxy.username, password=parsed_proxy.password)
        socket.socket = socks.socksocket

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, **kwargs)
        elif method == 'POST':
            response = requests.post(url, headers=headers, **kwargs)
        else:
            raise ValueError(f'Unsupported method: {method}')
        return response
    except Exception as e:
        print(f"Произошла ошибка при выполнении запроса: {e}")
        return None
 
# Основная функция
def main():
    w3 = Web3(Web3.HTTPProvider(ETH_NODE_RPC))

    eigen_token_address = w3.to_checksum_address("0xec53bF9167f50cDEB3Ae105f56099aaaB9061F83")
    strategy_manager_address = w3.to_checksum_address("0x858646372CC42E1A627fcE94aa7A7033e7CF075A")
    strategy_address = w3.to_checksum_address("0xaCB55C530Acdb2849e6d4f36992Cd8c9D50ED8F7")
    delegation_address = w3.to_checksum_address("0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A")
    claim_address = w3.to_checksum_address("0x035bdAeaB85E47710C27EdA7FD754bA80aD4ad02")
    our_operator = w3.to_checksum_address("0x9631af6a712D296FEdB800132EdcF08E493b12cD")

    private_keys = read_private_keys('pk.txt')
    proxies = read_proxies('proxies.txt') if USE_PROXY else []
    random.shuffle(private_keys)

    for private_key in private_keys:
        # Получение адреса из приватного ключа
        account = Account.from_key(private_key)
        address = account.address

        log(f"\n{address} started")

        # Проверка баланса
        balance_wei = w3.eth.get_balance(address)
        estimated_gas_cost = 540000 * (w3.eth.max_priority_fee + (2 * w3.eth.get_block('latest')['baseFeePerGas']))
        if balance_wei < estimated_gas_cost:
            log(f"Скорее всего, недостаточно баланса для выполнения транзакций. Баланс: {balance_wei}, Ориентировочная стоимость газа: {estimated_gas_cost}")
            #continue  # Пропускаем этот адрес

        need_too_sleep = False

        # прокси
        if proxies:
            proxy = random.choice(proxies)
            while True:
                public_ip = get_public_ip(proxy)
                if public_ip:
                    log(f'Using proxy: {proxy}, Public IP: {public_ip}')
                    break
                else:
                    log(f'Invalid proxy: {proxy}. Choosing another one...')
                    proxy = random.choice(proxies)
                    time.sleep(5) # Пауза 5 секунд
        else:
            proxy = None
            public_ip = get_public_ip()  # Получаем IP без прокси
            log(f'Public IP: {public_ip}')



        # Проверка и запрос наград
        with open('abi/0x035bdAeaB85E47710C27EdA7FD754bA80aD4ad02', 'r') as f:
            CLAIM_ABI = json.load(f)
        claim_contract = w3.eth.contract(address=claim_address, abi=CLAIM_ABI)
        has_claimed = claim_contract.functions.hasClaimed(address).call()

        if not has_claimed:
            log(f"Награды для адреса {address} еще не были запрошены. Запрашиваем...")

            # Шаг 1: Получение сообщения для подписи
            url = f'https://claims.eigenfoundation.org/clique-eigenlayer-api/auth/web3/signature?address={address}'
            response = make_request('GET', url, proxy)

            if response and not hasattr(response, 'error'): 
                data = response.json()
                message = data.get('message')

                if message:
                    # log(f'Address: {address}, Message: {message}')

                    # Шаг 2: Подписание сообщения
                    signature = sign_message(private_key, message)
                    # log(f'Signature: {signature}')

                    # Шаг 3: Авторизация
                    url = 'https://claims.eigenfoundation.org/clique-eigenlayer-api/auth/login/wallet'
                    data = {
                        'chainId': 1,
                        'address': address,
                        'signature': signature,
                        'accountType': 'eigenlayer'
                    }
                    response = make_request('POST', url, proxy, json=data)

                    if response and not hasattr(response, 'error'):
                        auth_data = response.json()
                        # log(f'Auth data: {json.dumps(auth_data, indent=4)}')

                        # Шаг 4: Получение данных о наградах
                        url = f'https://claims.eigenfoundation.org/clique-eigenlayer-api/campaign/eigenlayer/credentials?walletAddress={address}&signature={signature}&chainId=1'
                        response = make_request('GET', url, proxy)

                        if response and not hasattr(response, 'error'): 
                            credentials_data = response.json()
                            # log(f'Credentials data: {json.dumps(credentials_data, indent=4)}')

                            # Заявление наград
                            claim_data = credentials_data['claimData']
                            #contract_address = Web3.to_checksum_address(claim_data['contractAddress'])
                            #abi = claim_data['abi']
                            #contract = w3.eth.contract(address=contract_address, abi=abi)

                            amount = int(claim_data['amount'])
                            merkle_proof = claim_data['proof']
                            signature = claim_data['signature']

                            try:
                                tx = claim_contract.functions.claim(amount, merkle_proof, signature).build_transaction({
                                    'from': address,
                                    'nonce': w3.eth.get_transaction_count(address),
                                    'maxFeePerGas': w3.eth.max_priority_fee + (2 * w3.eth.get_block('latest')['baseFeePerGas']), 
                                    'maxPriorityFeePerGas': w3.eth.max_priority_fee, 
                                })

                                signed_tx = w3.eth.account.sign_transaction(tx, private_key)
                                tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                                log(f"Транзакция отправлена: {tx_hash.hex()}")

                                # Ожидание подтверждения транзакции
                                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                                if tx_receipt['status'] == 1:
                                    log(f"Награды успешно заявлены для адреса {address}. Сумма: {amount}")
                                    time.sleep(15)
                                    need_too_sleep = True
                                else:
                                    log(f"Ошибка при заявлении наград: {tx_receipt}")
                            except Exception as e:
                                log(f"Ошибка при вызове функции claim: {e}") 
                        else:
                            log(f'Error getting credentials data: {response.text if response else "No response"}')
                    else:
                        log(f'Error authorizing: {response.text if response else "No response"}')
                else:
                    log(f'Error getting message: {response.text if response else "No response"}')
            else:
                log(f'Error getting signature: {response.text if response else "No response"}')
        else:
            log(f"Награды для адреса {address} уже были запрошены.")



        # Депозит токена Eigen
        with open('abi/0xec53bF9167f50cDEB3Ae105f56099aaaB9061F83', 'r') as f:
            EIGEN_TOKEN_ABI = json.load(f)
        token_contract = w3.eth.contract(address=eigen_token_address, abi=EIGEN_TOKEN_ABI)
        balance_wei = token_contract.functions.balanceOf(address).call()
        decimals = token_contract.functions.decimals().call()
        balance = balance_wei / 10**decimals
        log(f"Баланс токена: {balance}")

        if balance > 1:
            # Проверка и аппрув
            approved = False

            allowance = token_contract.functions.allowance(address, strategy_manager_address).call()
            if allowance < balance_wei:
                log(f"Недостаточно аппрува для spender {strategy_manager_address}. Текущий аппрув: {allowance}. Делаем аппрув на {balance_wei}...")
                try:
                    tx = token_contract.functions.approve(strategy_manager_address, balance_wei).build_transaction({ # Исправлено: int(balance_wei)
                        'from': address,
                        'nonce': w3.eth.get_transaction_count(address),
                        'maxFeePerGas': w3.eth.max_priority_fee + (2 * w3.eth.get_block('latest')['baseFeePerGas']),
                        'maxPriorityFeePerGas': w3.eth.max_priority_fee,
                    })
                    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
                    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                    log(f"Транзакция аппрува отправлена: {tx_hash.hex()}")

                    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                    if tx_receipt['status'] == 1:
                        log(f"Аппрув успешно выполнен.")
                        time.sleep(15)
                        need_too_sleep = True
                        approved = True
                    else:
                        log(f"Ошибка при выполнении аппрува: {tx_receipt}")
                except Exception as e:
                    log(f"Ошибка при выполнении аппрува: {e}")
            else:
                approved = True
                log(f"Аппрув для spender {strategy_manager_address} достаточен.")

            if approved:
                # Вызов depositIntoStrategy
                with open('abi/0x858646372CC42E1A627fcE94aa7A7033e7CF075A', 'r') as f:
                    STRATEGY_MANAGER_ABI = json.load(f)
                strategy_manager_contract = w3.eth.contract(address=strategy_manager_address, abi=STRATEGY_MANAGER_ABI)
                try:
                    tx = strategy_manager_contract.functions.depositIntoStrategy(
                            strategy_address,
                            eigen_token_address,
                            balance_wei
                        ).build_transaction({
                            'from': address,
                            'nonce': w3.eth.get_transaction_count(address),
                            'maxFeePerGas': w3.eth.max_priority_fee + (2 * w3.eth.get_block('latest')['baseFeePerGas']),
                            'maxPriorityFeePerGas': w3.eth.max_priority_fee,
                    })
                    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
                    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                    log(f"Транзакция depositIntoStrategy отправлена: {tx_hash.hex()}")

                    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                    if tx_receipt['status'] == 1:
                        log(f"depositIntoStrategy успешно выполнен.")
                        time.sleep(15)
                        need_too_sleep = True
                    else:
                        log(f"Ошибка при вызове depositIntoStrategy: {tx_receipt}")
                except web3.exceptions.Web3Exception as e:  # Ловим все Web3Exception
                    log(f"Ошибка Web3 при вызове depositIntoStrategy: {e}")
                except Exception as e:
                    log(f"Ошибка при вызове depositIntoStrategy: {e}\n{traceback.format_exc()}")



        # Делегирование
        with open('abi/0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A', 'r') as f:
            DELEGATION_ABI = json.load(f)
        delegation_contract = w3.eth.contract(address=delegation_address, abi=DELEGATION_ABI)
        
        strategies, balances = delegation_contract.functions.getDelegatableShares(address).call()

        strategy_balance = 0
        for i, strat in enumerate(strategies):
            if strat == strategy_address:
                strategy_balance = balances[i]
                break

        if strategy_balance > 1:
            log(f"Баланс в стратегии: {strategy_balance}")

            delegated_operator = delegation_contract.functions.delegatedTo(address).call()

            if delegated_operator == "0x0000000000000000000000000000000000000000":
                log("Делегирование не настроено. Делегируем...")
                try:
                    tx = delegation_contract.functions.delegateTo(
                        our_operator,
                        ["0x", 0],
                        "0x0000000000000000000000000000000000000000000000000000000000000000"
                    ).build_transaction({
                        'from': address,
                        'nonce': w3.eth.get_transaction_count(address),
                        'maxFeePerGas': w3.eth.max_priority_fee + (2 * w3.eth.get_block('latest')['baseFeePerGas']),
                        'maxPriorityFeePerGas': w3.eth.max_priority_fee,
                    })

                    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
                    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                    log(f"Транзакция делегирования отправлена: {tx_hash.hex()}")

                    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                    if tx_receipt['status'] == 1:
                        log("Делегирование успешно выполнено.")
                        time.sleep(15)
                        need_too_sleep = True
                    else:
                        log(f"Ошибка при делегировании: {tx_receipt}")
                except Exception as e:
                    log(f"Ошибка при делегировании: {e}")
            elif delegated_operator == our_operator:
                log(f"Уже заделегировано на нашего оператора: {our_operator}")
            else:
                log(f"Сожалеем, уже заделегировано на другого оператора: {delegated_operator}")
        else:
            log(f"Баланс в стратегии недостаточен для делегирования: {strategy_balance}")

        
        # Сон
        if need_too_sleep:
            log(f"Спим...")
            time.sleep(random.randint(SLEEP_FROM, SLEEP_TO))
    
if __name__ == '__main__':
    main()
