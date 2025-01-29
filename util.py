from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import base58

MULTICODEC_PUBKEY_PREFIX = {
	ec.SECP256K1: b"\xe7\x01",  # varint(0xe7)
	ec.SECP256R1: b"\x80\x24",  # varint(0x1200)
}

def load_privkey(path: str) -> ec.EllipticCurvePrivateKey:
	with open(path, "rb") as keyfile:
		return serialization.load_pem_private_key(
			keyfile.read(),
			password=None
		)

def encode_pubkey_as_did_key(pubkey: ec.EllipticCurvePublicKey) -> str:
	compressed_public_bytes = pubkey.public_bytes(
		serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
	)
	multicodec = (
		MULTICODEC_PUBKEY_PREFIX[type(pubkey.curve)] + compressed_public_bytes
	)
	return "did:key:z" + base58.b58encode(multicodec).decode()
