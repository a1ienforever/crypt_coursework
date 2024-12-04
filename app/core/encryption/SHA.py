# app/core/sha256_hasher.py

import hashlib


class SHA256Hasher:
    @staticmethod
    def hash_data(data: bytes) -> str:
        """
        Генерирует SHA-256 хеш для переданных данных.
        :param data: Данные для хеширования в виде байтов.
        :return: Хеш в виде строки (hex).
        """
        if not isinstance(data, bytes):
            raise TypeError("Данные должны быть переданы в виде байтов.")
        sha256_hash = hashlib.sha256(data).hexdigest()
        return sha256_hash

    @staticmethod
    def verify_hash(data: bytes, expected_hash: str) -> bool:
        """
        Проверяет, соответствует ли хеш переданных данных ожидаемому хешу.
        :param data: Данные для проверки.
        :param expected_hash: Ожидаемый хеш в виде строки (hex).
        :return: True, если хеш совпадает, иначе False.
        """
        if not isinstance(data, bytes):
            raise TypeError("Данные должны быть переданы в виде байтов.")
        if not isinstance(expected_hash, str):
            raise TypeError("Ожидаемый хеш должен быть строкой.")
        actual_hash = SHA256Hasher.hash_data(data)
        return actual_hash == expected_hash
