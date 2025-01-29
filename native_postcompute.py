import hashlib
import base64
import cbrrr
import json

import secp256k1
import util

HALF_N = secp256k1.n // 2


def main(expected_did: str, handle_tweak: str, k_inv: int):
	privkey = util.load_privkey("privkey.pem")
	pubkey = privkey.public_key()
	#print(util.encode_pubkey_as_did_key(pubkey))
	private_scalar = privkey.private_numbers().private_value

	genesis = {
		"prev": None,
		"type": "plc_operation",
		"services": {},
		"alsoKnownAs": ["at://" + handle_tweak],
		"rotationKeys": [util.encode_pubkey_as_did_key(pubkey)],
		"verificationMethods": {},
	}
	#print(cbrrr.encode_dag_cbor(genesis))
	z = int.from_bytes(hashlib.sha256(cbrrr.encode_dag_cbor(genesis)).digest())

	k = pow(k_inv, -1, secp256k1.n)
	R = secp256k1.G.scalar_mul(k)
	r = R.x
	rDa = (r * private_scalar) % secp256k1.n
	s = (k_inv * (z + rDa)) % secp256k1.n
	if s > HALF_N:
		s = secp256k1.n - s

	raw_sig = r.to_bytes(32) + s.to_bytes(32)

	genesis["sig"] = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()
	signed_msg = cbrrr.encode_dag_cbor(genesis)
	digest = hashlib.sha256(signed_msg).digest()
	plc = base64.b32encode(digest[:15]).lower().decode()

	if plc != expected_did:
		print(plc, "!=", expected_did)
		raise Exception("something went wrong")

	#print("did:plc:" + plc)

	signed_genesis = cbrrr.decode_dag_cbor(signed_msg)
	outpath = f"signed_genesis_{plc}.json"
	with open(outpath, "w") as json_out:
		json.dump(signed_genesis, json_out, indent=4)

	# sanity check:
	raw_sig = base64.urlsafe_b64decode(signed_genesis.pop("sig") + "==")
	pubkey.verify(
		util.encode_dss_signature(
			int.from_bytes(raw_sig[:32]),
			int.from_bytes(raw_sig[32:])
		),
		cbrrr.encode_dag_cbor(signed_genesis),
		util.DETERMINISTIC_ECDSA_SHA256
	)

	print(f"your signed genesis op is at {outpath!r} and ready to be published")

if __name__ == "__main__":
	import sys
	if len(sys.argv) != 4:
		print(f"USAGE: {sys.argv[0]} expected_did handle_tweak k_inv")
		print("(i.e. a line of output from mine.c)")
	else:
		expected_did, handle_tweak, k_inv = sys.argv[1:4]
		main(expected_did, handle_tweak, int(k_inv, 0))
