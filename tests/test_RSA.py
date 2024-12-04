# tests/test_rsa_cipher.py

import unittest
import os
import tempfile

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from app.core.encryption.RSA import RSACipher


class TestRSACipher(unittest.TestCase):
    def setUp(self):
        """
        Инициализация перед каждым тестом.
        """
        self.cipher = RSACipher()
        self.message = "Тестовое сообщение для RSA шифрования и подписания.".encode('utf-8')

    def test_key_generation(self):
        """
        Проверка генерации ключей.
        """
        self.assertIsNotNone(self.cipher.private_key, "Приватный ключ не сгенерирован.")
        self.assertIsNotNone(self.cipher.public_key, "Публичный ключ не сгенерирован.")

    def test_encrypt_decrypt(self):
        """
        Проверка, что расшифрованный текст совпадает с исходным.
        """
        ciphertext = self.cipher.encrypt(self.message)
        decrypted_message = self.cipher.decrypt(ciphertext)
        self.assertEqual(self.message, decrypted_message, "Расшифрованное сообщение не совпадает с исходным.")

    def test_encrypt_different_outputs(self):
        """
        Проверка, что два шифрования одного и того же сообщения дают разные результаты (из-за OAEP padding).
        """
        ciphertext1 = self.cipher.encrypt(self.message)
        ciphertext2 = self.cipher.encrypt(self.message)
        self.assertNotEqual(ciphertext1, ciphertext2, "Шифротексты должны отличаться из-за разного padding.")

    def test_decrypt_with_wrong_key(self):
        """
        Проверка, что дешифрование с неправильным приватным ключом вызывает ошибку.
        """
        wrong_cipher = RSACipher()
        ciphertext = self.cipher.encrypt(self.message)
        with self.assertRaises(Exception, msg="Дешифрование с неправильным ключом должно вызвать ошибку."):
            wrong_cipher.decrypt(ciphertext)

    def test_sign_verify(self):
        """
        Проверка создания и верификации подписи.
        """
        signature = self.cipher.sign(self.message)
        is_valid = self.cipher.verify(self.message, signature)
        self.assertTrue(is_valid, "Подпись должна быть валидной.")

    def test_verify_with_wrong_signature(self):
        """
        Проверка, что проверка подписи с неверной подписью возвращает False.
        """
        signature = self.cipher.sign(self.message)
        tampered_message = "Измененное сообщение.".encode('utf-8')
        is_valid = self.cipher.verify(tampered_message, signature)
        self.assertFalse(is_valid, "Подпись для измененного сообщения должна быть невалидной.")

    def test_save_and_load_keys(self):
        """
        Проверка сохранения и загрузки ключей.
        """
        with tempfile.TemporaryDirectory() as tmpdirname:
            private_key_path = os.path.join(tmpdirname, "private_key.pem")
            public_key_path = os.path.join(tmpdirname, "public_key.pem")
            password = b"secure_password"

            # Сохранение ключей
            self.cipher.save_keys(private_key_path, public_key_path, password=password)

            # Проверка, что файлы созданы
            self.assertTrue(os.path.exists(private_key_path), "Приватный ключ не сохранен.")
            self.assertTrue(os.path.exists(public_key_path), "Публичный ключ не сохранен.")

            # Загрузка ключей
            loaded_private_key, loaded_public_key = RSACipher.load_keys(
                private_key_path, public_key_path, password=password
            )

            # Создание нового объекта RSACipher с загруженными ключами
            loaded_cipher = RSACipher(private_key=loaded_private_key, public_key=loaded_public_key)

            # Проверка шифрования и дешифрования с загруженными ключами
            ciphertext = loaded_cipher.encrypt(self.message)
            decrypted_message = loaded_cipher.decrypt(ciphertext)
            self.assertEqual(self.message, decrypted_message, "Расшифрованное сообщение с загруженными ключами не совпадает с исходным.")

    def test_save_keys_without_password(self):
        """
        Проверка сохранения ключей без пароля.
        """
        with tempfile.TemporaryDirectory() as tmpdirname:
            private_key_path = os.path.join(tmpdirname, "private_key.pem")
            public_key_path = os.path.join(tmpdirname, "public_key.pem")

            # Сохранение ключей без пароля
            self.cipher.save_keys(private_key_path, public_key_path)

            # Загрузка ключей
            loaded_private_key, loaded_public_key = RSACipher.load_keys(
                private_key_path, public_key_path
            )

            # Создание нового объекта RSACipher с загруженными ключами
            loaded_cipher = RSACipher(private_key=loaded_private_key, public_key=loaded_public_key)

            # Проверка шифрования и дешифрования с загруженными ключами
            ciphertext = loaded_cipher.encrypt(self.message)
            decrypted_message = loaded_cipher.decrypt(ciphertext)
            self.assertEqual(self.message, decrypted_message, "Расшифрованное сообщение с загруженными ключами без пароля не совпадает с исходным.")

    def test_load_keys_with_wrong_password(self):
        """
        Проверка, что загрузка приватного ключа с неправильным паролем вызывает ошибку.
        """
        with tempfile.TemporaryDirectory() as tmpdirname:
            private_key_path = os.path.join(tmpdirname, "private_key.pem")
            public_key_path = os.path.join(tmpdirname, "public_key.pem")
            correct_password = b"correct_password"
            wrong_password = b"wrong_password"

            # Сохранение ключей с правильным паролем
            self.cipher.save_keys(private_key_path, public_key_path, password=correct_password)

            # Попытка загрузки с неправильным паролем
            with self.assertRaises(ValueError, msg="Загрузка ключа с неправильным паролем должна вызвать ValueError."):
                RSACipher.load_keys(private_key_path, public_key_path, password=wrong_password)

    def test_load_keys_without_password_when_encrypted(self):
        """
        Проверка, что загрузка зашифрованного приватного ключа без пароля вызывает ошибку.
        """
        with tempfile.TemporaryDirectory() as tmpdirname:
            private_key_path = os.path.join(tmpdirname, "private_key.pem")
            public_key_path = os.path.join(tmpdirname, "public_key.pem")
            password = b"secure_password"

            # Сохранение ключей с паролем
            self.cipher.save_keys(private_key_path, public_key_path, password=password)

            # Попытка загрузки без пароля
            with self.assertRaises(TypeError, msg="Загрузка зашифрованного ключа без пароля должна вызвать TypeError."):
                RSACipher.load_keys(private_key_path, public_key_path)

    def test_encrypt_with_empty_message(self):
        """
        Проверка, что шифрование пустого сообщения работает корректно.
        """
        empty_message = b""
        ciphertext = self.cipher.encrypt(empty_message)
        decrypted_message = self.cipher.decrypt(ciphertext)
        self.assertEqual(empty_message, decrypted_message, "Расшифрованное пустое сообщение не совпадает с исходным.")

    def test_sign_empty_message(self):
        """
        Проверка, что подпись пустого сообщения работает корректно.
        """
        empty_message = b""
        signature = self.cipher.sign(empty_message)
        is_valid = self.cipher.verify(empty_message, signature)
        self.assertTrue(is_valid, "Подпись пустого сообщения должна быть валидной.")

    def test_verify_with_tampered_signature(self):
        """
        Проверка, что подпись, измененная после создания, не проходит верификацию.
        """
        signature = self.cipher.sign(self.message)
        tampered_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])  # Изменение последнего байта
        is_valid = self.cipher.verify(self.message, tampered_signature)
        self.assertFalse(is_valid, "Измененная подпись должна быть невалидной.")


if __name__ == "__main__":
    unittest.main()
