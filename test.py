from py_vapid import Vapid
import base64
from cryptography.hazmat.primitives import serialization

def to_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
vapid = Vapid()
vapid.generate_keys()
private_key = vapid.private_key
public_key = vapid.public_key

priv_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,  # PrivateFormat.TraditionalOpenSSL
    encryption_algorithm=serialization.NoEncryption()  # NoEncryption()
)

public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo  # PublicFormat.SubjectPublicKeyInfo
)

print("VAPID_PRIVATE_KEY:", to_base64url(priv_bytes))
print("VAPID_PUBLIC_KEY:", to_base64url(public_bytes))
