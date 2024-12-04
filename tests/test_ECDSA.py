import unittest
from ecdsa import SigningKey, VerifyingKey

from app.core.encryption.ECSDA import ECDSASignature


class TestECDSASignature(unittest.TestCase):
    def setUp(self):
        self.message = "Тестовое сообщение для подписи.".encode()
        self.private_key, self.public_key = ECDSASignature.generate_keys()

    def test_sign_and_verify(self):
        signature = ECDSASignature.sign_message(self.private_key, self.message)
        self.assertTrue(
            ECDSASignature.verify_signature(self.public_key, self.message, signature),
            "Подпись должна быть валидной.",
        )

    def test_invalid_signature(self):
        fake_message = "Другое сообщение.".encode()
        signature = ECDSASignature.sign_message(self.private_key, self.message)
        self.assertFalse(
            ECDSASignature.verify_signature(self.public_key, fake_message, signature),
            "Подпись не должна быть валидной для другого сообщения.",
        )

    def test_invalid_message_type(self):
        with self.assertRaises(TypeError, msg="Должно возникнуть исключение TypeError."):
            ECDSASignature.sign_message(self.private_key, "Некорректные данные")

    def test_invalid_signature_verification(self):
        with self.assertRaises(TypeError, msg="Должно возникнуть исключение TypeError."):
            ECDSASignature.verify_signature(self.public_key, "Некорректные данные", b"")


if __name__ == "__main__":
    unittest.main()
