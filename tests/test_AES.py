import unittest
import os

from app.core.encryption.AES import AESCipher


class TestAESCipher(unittest.TestCase):

    def setUp(self):
        """
        Инициализация перед каждым тестом.
        """
        # Генерация ключа длиной 32 байта (AES-256)
        self.key = os.urandom(32)
        self.cipher = AESCipher(self.key)
        self.sample_text = "Тестовое сообщение для шифрования".encode("utf-8")  # Исправлено

    def test_encrypt_decrypt(self):
        """
        Проверка, что данные после шифрования и расшифрования совпадают с исходными.
        """
        encrypted_data = self.cipher.encrypt(self.sample_text)
        decrypted_data = self.cipher.decrypt(encrypted_data)

        self.assertEqual(self.sample_text, decrypted_data, "Расшифрованные данные не совпадают с исходными")

    def test_encrypt_different_outputs(self):
        """
        Проверка, что два вызова шифрования одной и той же строки дают разные результаты (из-за IV).
        """
        encrypted_data1 = self.cipher.encrypt(self.sample_text)
        encrypted_data2 = self.cipher.encrypt(self.sample_text)

        self.assertNotEqual(encrypted_data1, encrypted_data2, "Шифротексты должны отличаться из-за разного IV")

    def test_decrypt_with_wrong_key(self):
        """
        Проверка, что дешифрование с неправильным ключом вызывает ошибку.
        """
        wrong_key = os.urandom(32)
        wrong_cipher = AESCipher(wrong_key)
        encrypted_data = self.cipher.encrypt(self.sample_text)

        with self.assertRaises(Exception, msg="Дешифрование с неправильным ключом должно вызывать ошибку"):
            wrong_cipher.decrypt(encrypted_data)

    def test_invalid_key_length(self):
        """
        Проверка, что передача ключа неверной длины вызывает ValueError.
        """
        with self.assertRaises(ValueError, msg="Ключ длиной менее 16 байт должен вызывать ValueError"):
            AESCipher(b"shortkey")

        with self.assertRaises(ValueError, msg="Ключ длиной более 32 байт должен вызывать ValueError"):
            AESCipher(os.urandom(40))

    def test_decrypt_invalid_data(self):
        """
        Проверка, что дешифрование некорректных данных вызывает ошибку.
        """
        invalid_data = b"corrupted_data"

        with self.assertRaises(Exception, msg="Попытка дешифрования некорректных данных должна вызывать ошибку"):
            self.cipher.derypt(invalid_data)


if __name__ == "__main__":
    unittest.main()
