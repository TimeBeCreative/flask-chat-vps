from py_vapid import Vapid
import base64
from cryptography.hazmat.primitives import serialization

def to_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
vapid = Vapid()
vapid.generate_keys()


priv_bytes = vapid.private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,  # PrivateFormat.TraditionalOpenSSL
    encryption_algorithm=serialization.NoEncryption()  # NoEncryption()
)

public_bytes = vapid.public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint  
)

print("VAPID_PRIVATE_KEY:", to_base64url(priv_bytes))
print("VAPID_PUBLIC_KEY:", to_base64url(public_bytes))
