import ecdsa
import os

KEYS_DIR = os.path.join('cipher', 'ecc', 'keys')
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, 'privateKey.pem')
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, 'publicKey.pem')

if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)

class ECCCipher:
    def __init__(self):
        pass

    def generate_keys(self):
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)  # Chỉ định curve rõ ràng
        vk = sk.get_verifying_key()

        with open(PRIVATE_KEY_PATH, 'wb') as p:
            p.write(sk.to_pem())

        with open(PUBLIC_KEY_PATH, 'wb') as p:
            p.write(vk.to_pem())

    def load_keys(self):
        with open(PRIVATE_KEY_PATH, 'rb') as p:
            sk = ecdsa.SigningKey.from_pem(p.read())

        with open(PUBLIC_KEY_PATH, 'rb') as p:
            vk = ecdsa.VerifyingKey.from_pem(p.read())

        return {'private_key': sk, 'public_key': vk}

    def sign(self, message, key):
        # Ký dữ liệu bằng khóa riêng tư, dùng utf-8 để hỗ trợ Unicode
        return key.sign(message.encode('utf-8'))

    def verify(self, message, signature, key):
        try:
            return key.verify(signature, message.encode('utf-8'))
        except ecdsa.BadSignatureError:
            return False
        except Exception:
            return False