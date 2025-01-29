import secrets
import secp256k1

import util

def precompute_r_rDa_kinv(private_scalar, count=100_000):
	table = []
	k = secrets.randbelow(secp256k1.n)
	R = secp256k1.G.scalar_mul(k)
	k_inv = pow(k, -1, secp256k1.n)
	div2 = pow(2, -1, secp256k1.n)
	for _ in range(count):
		k_inv = (k_inv * div2) % secp256k1.n
		R += R
		r = R.x
		rDa = (r * private_scalar) % secp256k1.n
		table.append((r.to_bytes(32), rDa, k_inv))
	return table

privkey = util.load_privkey("privkey.pem")
private_scalar = privkey.private_numbers().private_value
r_rDa_kinv = precompute_r_rDa_kinv(private_scalar)

with open("precomputed.bin", "wb") as outfile:
	for r_bytes, rDa, k_inv in r_rDa_kinv:
		outfile.write(r_bytes + rDa.to_bytes(32) + k_inv.to_bytes(32))

print("precomputed tables for DID pubkey:")
print(util.encode_pubkey_as_did_key(privkey.public_key()))
