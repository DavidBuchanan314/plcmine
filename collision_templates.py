import cbrrr
from cryptography.hazmat.primitives.asymmetric import ec
import secrets
import base64
import hashlib

import secp256k1
import util


def sha256_prepare(msg: bytes):
	buf = msg
	buf += b"\x80"
	buf += b"\x00" * ((-8-len(buf))%64)
	arr = [int.from_bytes(buf[i:i+4], "big") for i in range(0, len(buf), 4)]
	arr += [0, len(msg)*8]
	for i in range(0, len(arr), 16):
		print(f"uint32 buf[0x10] = {{" + ", ".join(f"0x{n:08x}" for n in arr[i:i+16]) + "};")


TWEAKLEN = 14*2 # worst case
TWEAKLEN += 10

privkey = ec.generate_private_key(ec.SECP256K1())
pubkey_str = util.encode_pubkey_as_did_key(privkey.public_key())

unsigned_genesis = {
	"prev": None,
	"type": "plc_operation",
	"services": {},
	"alsoKnownAs": ["A"*TWEAKLEN],
	"rotationKeys": [pubkey_str],
	"verificationMethods": {},
}
unsigned_genesis_bytes = cbrrr.encode_dag_cbor(unsigned_genesis)
print(unsigned_genesis_bytes)
sha256_prepare(unsigned_genesis_bytes)
print(hashlib.sha256(unsigned_genesis_bytes).hexdigest())
unsigned_a, unsigned_b = unsigned_genesis_bytes.split(b"A"*TWEAKLEN)

private_scalar = privkey.private_numbers().private_value
k = secrets.randbelow(secp256k1.n)
R = secp256k1.G.scalar_mul(k)
r = R.x
r_bytes = r.to_bytes(32, "big")
r_b64 = base64.urlsafe_b64encode(r_bytes[:30])
r_bytes_suffix = r_bytes[30:]

signed_gensis_template = {
	"sig": r_b64.decode() + "B"*46,
	"prev": None,
	"type": "plc_operation",
	"services": {},
	"alsoKnownAs": ["A"*TWEAKLEN],
	"rotationKeys": [pubkey_str],
	"verificationMethods": {},
}
signed_gensis_template_bytes = cbrrr.encode_dag_cbor(signed_gensis_template)
print(signed_gensis_template_bytes)
sha256_prepare(signed_gensis_template_bytes)
