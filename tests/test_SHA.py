# tests/test_sha256_hasher.py

import unittest

from app.core.encryption.SHA import SHA256Hasher


class TestSHA256Hasher(unittest.TestCase):
    def setUp(self):
        """
        Инициализация данных для тестов.
        """
        self.data = "Тестовые данные для хеширования".encode('utf-8')
        self.expected_hash = (
            "991edefcec68d198f7c0719e54daf8b87112e6fe5896be61b7285048f535229e"
        )

    def test_hash_data(self):
        """
        Проверка корректности генерации хеша.
        """
        result = SHA256Hasher.hash_data(self.data)
        self.assertEqual(
            result, self.expected_hash, "Сгенерированный хеш не совпадает с ожидаемым."
        )

    def test_hash_data_type_error(self):
        """
        Проверка выброса исключения при передаче данных неправильного типа.
        """
        with self.assertRaises(TypeError, msg="Должно возникнуть исключение TypeError."):
            SHA256Hasher.hash_data("Некорректные данные".encode())  # Передаем строку вместо байтов.

    def test_verify_hash_correct(self):
        """
        Проверка успешной верификации хеша.
        """
        is_valid = SHA256Hasher.verify_hash(self.data, self.expected_hash)
        self.assertTrue(is_valid, "Хеш должен быть валидным.")

    def test_verify_hash_incorrect(self):
        """
        Проверка неуспешной верификации хеша.
        """
        wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        is_valid = SHA256Hasher.verify_hash(self.data, wrong_hash)
        self.assertFalse(is_valid, "Хеш не должен быть валидным для неправильного значения.")

    def test_verify_hash_type_error_data(self):
        """
        Проверка выброса исключения при передаче некорректного типа данных.
        """
        with self.assertRaises(TypeError, msg="Должно возникнуть исключение TypeError."):
            SHA256Hasher.verify_hash("Некорректные данные", self.expected_hash)

    def test_verify_hash_type_error_expected_hash(self):
        """
        Проверка выброса исключения при передаче хеша неправильного типа.
        """
        with self.assertRaises(TypeError, msg="Должно возникнуть исключение TypeError."):
            SHA256Hasher.verify_hash(self.data, 12345)


if __name__ == "__main__":
    unittest.main()
