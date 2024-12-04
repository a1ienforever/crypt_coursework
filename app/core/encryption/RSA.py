from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


class RSACipher:
    def __init__(self, private_key=None, public_key=None):
        """
        Инициализация RSA. Генерация пары ключей, если они не переданы.
        """
        if private_key is None or public_key is None:
            self.private_key, self.public_key = self.generate_keys()
        else:
            self.private_key = private_key
            self.public_key = public_key

    @staticmethod
    def generate_keys():
        """
        Генерация пары RSA-ключей (приватного и публичного).
        :return: (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Шифрование данных с помощью открытого ключа.
        :param plaintext: Исходные данные.
        :return: Зашифрованные данные.
        """
        return self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Дешифрование данных с помощью приватного ключа.
        :param ciphertext: Зашифрованные данные.
        :return: Исходные данные.
        """
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def sign(self, message: bytes) -> bytes:
        """
        Создание цифровой подписи.
        :param message: Сообщение для подписи.
        :return: Подпись.
        """
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Проверка цифровой подписи.
        :param message: Сообщение.
        :param signature: Подпись.
        :return: True, если подпись корректна, иначе False.
        """
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def save_keys(self, private_key_path: str, public_key_path: str, password: bytes = None):
        """
        Сохранение ключей в файлы.
        :param private_key_path: Путь для приватного ключа.
        :param public_key_path: Путь для публичного ключа.
        :param password: Пароль для шифрования приватного ключа (опционально).
        """
        # Сохранение приватного ключа
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        with open(private_key_path, "wb") as private_file:
            private_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algorithm,
                )
            )

        # Сохранение публичного ключа
        with open(public_key_path, "wb") as public_file:
            public_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    @staticmethod
    def load_keys(private_key_path: str, public_key_path: str, password: bytes = None):
        """
        Загрузка ключей из файлов.
        :param private_key_path: Путь к приватному ключу.
        :param public_key_path: Путь к публичному ключу.
        :param password: Пароль для дешифрования приватного ключа (опционально).
        :return: (private_key, public_key)
        """
        # Загрузка приватного ключа
        with open(private_key_path, "rb") as private_file:
            private_key = serialization.load_pem_private_key(
                private_file.read(),
                password=password,
            )

        # Загрузка публичного ключа
        with open(public_key_path, "rb") as public_file:
            public_key = serialization.load_pem_public_key(public_file.read())

        return private_key, public_key
