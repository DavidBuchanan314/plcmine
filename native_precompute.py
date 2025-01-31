import secrets

import secp256k1
import util

def precompute_r_rDa_kinv(private_scalar, count=100_000, k=None):
	table = []
	if k is None:
		k = secrets.randbelow(secp256k1.n)
	else:
		print("WARNING: running with hardcoded k constant, should only be used during testing")
	R = secp256k1.G.scalar_mul(k)
	k_inv = pow(k, -1, secp256k1.n)
	div2 = pow(2, -1, secp256k1.n)
	for _ in range(count):
		k_inv = (k_inv * div2) % secp256k1.n
		R += R
		r = R.x
		rDa = (r * private_scalar) % secp256k1.n
		k_inv_rDa = (k_inv * rDa) % secp256k1.n
		table.append((r.to_bytes(32), k_inv_rDa, k_inv))
	return table

def main(testmode: bool):
	privkey = util.load_privkey("privkey.pem")
	private_scalar = privkey.private_numbers().private_value

	if testmode:
		print("WARNING: RUNNING IN TEST MODE - THIS IS CRYPTOGRAPHICALLY INSECURE")
		#      ^(because k is fixed, for determinism)
		r_kinvrDa_kinv = precompute_r_rDa_kinv(private_scalar, count=10_000, k=12345)
	else:
		r_kinvrDa_kinv = precompute_r_rDa_kinv(private_scalar)

	with open("precomputed.bin", "wb") as outfile:
		for r_bytes, k_inv_rDa, k_inv in r_kinvrDa_kinv:
			outfile.write(r_bytes + k_inv_rDa.to_bytes(32) + k_inv.to_bytes(32))

	print("precomputed tables for DID pubkey:")
	print(util.encode_pubkey_as_did_key(privkey.public_key()))

if __name__ == "__main__":
	import sys
	testmode = sys.argv[-1] == "testmode"
	main(testmode)
