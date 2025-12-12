import hashlib
import base58
import sys
import argparse
from mnemonic import Mnemonic
from bip32 import BIP32
from ecdsa import SECP256k1, SigningKey
from Crypto.Hash import keccak

# ------------------------------------------------------------------------
# КОНФИГУРАЦИЯ
# ------------------------------------------------------------------------
# Путь с вашего фото (Ethereum coin_type = 60)
DERIVATION_PATH = "m/44'/60'/0'/0/0" 

# ------------------------------------------------------------------------
# ФУНКЦИИ ГЕНЕРАЦИИ
# ------------------------------------------------------------------------

def get_private_key(mnemonic_phrase: str, path: str) -> bytes:
    """Генерирует приватный ключ из мнемоники по заданному пути."""
    mnemo = Mnemonic("english")
    # Проверка валидности мнемоники (опционально, но полезно)
    if not mnemo.check(mnemonic_phrase):
        raise ValueError("Invalid Mnemonic Checksum or Word")

    seed = mnemo.to_seed(mnemonic_phrase, passphrase="")
    
    # Генерация мастер-ключа и спуск по пути деривации
    bip32_ctx = BIP32.from_seed(seed)
    private_key = bip32_ctx.get_privkey_from_path(path)
    return private_key

def private_key_to_tron_address(private_key_bytes: bytes) -> str:
    """Превращает приватный ключ в TRON адрес (Base58Check)."""
    
    # 1. Получаем публичный ключ (64 байта, Uncompressed, без префикса 04)
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    public_key_bytes = sk.verifying_key.to_string() 
    
    # 2. Keccak-256 хэш от публичного ключа
    k = keccak.new(digest_bits=256)
    k.update(public_key_bytes)
    pub_key_hash = k.digest()
    
    # 3. Берем последние 20 байт
    address_body = pub_key_hash[-20:]
    
    # 4. Добавляем префикс 0x41 (TRON Mainnet)
    tron_prefix = b'\x41'
    raw_address = tron_prefix + address_body
    
    # 5. Вычисляем контрольную сумму (Double SHA256)
    sha_1 = hashlib.sha256(raw_address).digest()
    sha_2 = hashlib.sha256(sha_1).digest()
    checksum = sha_2[:4]
    
    # 6. Склеиваем и кодируем в Base58
    final_binary = raw_address + checksum
    final_address = base58.b58encode(final_binary).decode('utf-8')
    
    return final_address

# ------------------------------------------------------------------------
# БЛОК ПРОВЕРКИ (AUDIT)
# ------------------------------------------------------------------------

def verify_integrity():
    """Проверяет работу скрипта на известном векторе."""
    print("--- Запуск самодиагностики... ", end="")
    test_mnemo = "test test test test test test test test test test test junk"
    test_path = "m/44'/60'/0'/0/0"
    expected_tron = "TYBNgWfhGuNzdLtjKtxXTfskAhTbMcqbaG" # Correct for Path 60'
    
    try:
        priv = get_private_key(test_mnemo, test_path)
        addr = private_key_to_tron_address(priv)
        if addr == expected_tron:
            print("[OK] ---")
            return True
        else:
            print(f"\n[FAIL] Ожидалось: {expected_tron}, Получено: {addr}")
            return False
    except Exception as e:
        print(f"\n[CRITICAL ERROR] {e}")
        return False

# ------------------------------------------------------------------------
# ОБРАБОТКА ФАЙЛА
# ------------------------------------------------------------------------

def process_file(input_file, output_file):
    print(f"Чтение из: {input_file}")
    print(f"Запись в:  {output_file}")
    
    count_ok = 0
    count_err = 0

    try:
        with open(input_file, 'r', encoding='utf-8') as f_in, \
             open(output_file, 'w', encoding='utf-8') as f_out:
            
            for line_num, line in enumerate(f_in, 1):
                phrase = line.strip()
                if not phrase:
                    continue # Пропуск пустых строк

                try:
                    pk = get_private_key(phrase, DERIVATION_PATH)
                    address = private_key_to_tron_address(pk)
                    
                    # Формат вывода: фраза / адрес
                    f_out.write(f"{phrase} / {address}\n")
                    
                    # Вывод прогресса в консоль (каждые 100 строк)
                    if line_num % 100 == 0:
                        print(f"Обработано {line_num} строк...")
                    
                    count_ok += 1

                except ValueError:
                    error_msg = f"{phrase} / ERROR_INVALID_MNEMONIC"
                    f_out.write(error_msg + "\n")
                    print(f"[Warn] Строка {line_num}: Неверная мнемоника")
                    count_err += 1
                except Exception as e:
                    error_msg = f"{phrase} / ERROR_UNKNOWN: {str(e)}"
                    f_out.write(error_msg + "\n")
                    print(f"[Err] Строка {line_num}: {e}")
                    count_err += 1
                    
        print(f"\nГотово! Успешно: {count_ok}, Ошибок: {count_err}")
        print(f"Результат сохранен в {output_file}")

    except FileNotFoundError:
        print(f"Ошибка: Файл '{input_file}' не найден.")
    except Exception as e:
        print(f"Критическая ошибка при работе с файлами: {e}")

# ------------------------------------------------------------------------
# ЗАПУСК
# ------------------------------------------------------------------------

if __name__ == "__main__":
    # Аргументы командной строки
    parser = argparse.ArgumentParser(description="Generate TRON addresses from seed phrases file.")
    parser.add_argument("-i", "--input", required=True, help="Путь к файлу с фразами")
    parser.add_argument("-o", "--output", default="results.txt", help="Путь к файлу результата (по умолчанию results.txt)")
    
    args = parser.parse_args()

    # Сначала проверяем математику
    if not verify_integrity():
        sys.exit("Скрипт остановлен из-за ошибки верификации.")

    # Запускаем обработку
    process_file(args.input, args.output)

