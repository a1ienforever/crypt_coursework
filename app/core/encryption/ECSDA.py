from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError


class ECDSASignature:
    @staticmethod
    def generate_keys():
        """
        Генерация пары ключей: приватного и публичного.
        :return: (SigningKey, VerifyingKey) - пара ключей.
        """
        private_key = SigningKey.generate(curve=NIST256p)
        public_key = private_key.get_verifying_key()
        return private_key, public_key

    @staticmethod
    def sign_message(private_key: SigningKey, message: bytes) -> bytes:
        """
        Подпись сообщения с использованием приватного ключа.
        :param private_key: Приватный ключ для подписи.
        :param message: Сообщение в виде байтов.
        :return: Подпись в виде байтов.
        """
        if not isinstance(message, bytes):
            raise TypeError("Сообщение должно быть в формате байтов.")
        return private_key.sign(message)

    @staticmethod
    def verify_signature(public_key: VerifyingKey, message: bytes, signature: bytes) -> bool:
        """
        Проверка подписи с использованием публичного ключа.
        :param public_key: Публичный ключ для проверки.
        :param message: Оригинальное сообщение.
        :param signature: Подпись, которую нужно проверить.
        :return: True, если подпись валидна, иначе False.
        """
        if not isinstance(message, bytes):
            raise TypeError("Сообщение должно быть в формате байтов.")
        try:
            return public_key.verify(signature, message)
        except BadSignatureError:
            return False
