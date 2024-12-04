import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AESCipher:
    def __init__(self, key: bytes):
        """
        Инициализация AES-шифра.
        :param key: Ключ для шифрования (должен быть 16, 24 или 32 байта).
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError("Ключ должен быть длиной 16, 24 или 32 байта.")
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Шифрование данных с помощью AES.
        :param plaintext: Данные для шифрования.
        :return: Зашифрованные данные (IV + ciphertext).
        """
        # Добавляем отступы
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Генерируем случайный IV (Initialization Vector)
        iv = os.urandom(16)

        # Настраиваем шифратор
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Возвращаем IV + шифротекст
        return iv + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Дешифрование данных с помощью AES.
        :param encrypted_data: Зашифрованные данные (IV + ciphertext).
        :return: Исходные данные (plaintext).
        """
        # Извлекаем IV и шифротекст
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Настраиваем расшифровщик
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Удаляем отступы
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext
