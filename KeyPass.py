import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def gen_key(ki):
    password_provided = ki
    password = password_provided.encode()
    salt = b'SIESCOMS'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    # print(key)

    file = open('Keys/gen.key', 'wb')
    file.write(key)
    file.close()
