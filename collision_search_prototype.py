import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
import os
from multiprocessing import Queue, Process
from typing import Tuple
import secrets
import base64
import json
import math
import time

from tqdm import tqdm
import cbrrr

import secp256k1
import util

HALF_N = secp256k1.n//2

NUM_WORKERS = 8
HASH_LENGTH_BITS = 5 * 10
HASH_LENGH_BYTES = (HASH_LENGTH_BITS + 7) // 8
HASH_END_MASK = (0xff<<(8-(HASH_LENGTH_BITS % 8))) & 0xff

TWEAKLEN = HASH_LENGH_BYTES*2 - 2  # hex encoded because it's cheap

# Precompute data for a set of 256 different private keys.
# Each attempt will pick a random private key, so when we find a collision,
# there's a good chance (1-(1/256)) that each side will be using a different key.
def precompute_lut(count=256):
	lut = []
	for _ in tqdm(range(count), "Precompute LUT"):
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
		unsigned_a, unsigned_b = unsigned_genesis_bytes.split(b"A"*TWEAKLEN)

		private_scalar = privkey.private_numbers().private_value
		k = secrets.randbelow(secp256k1.n)
		R = secp256k1.G.scalar_mul(k)
		r = R.x
		r_bytes = r.to_bytes(32, "big")
		r_b64 = base64.urlsafe_b64encode(r_bytes[:30])
		r_bytes_suffix = r_bytes[30:]

		signed_gensis_template = {
			"sig": r_b64.decode() + "A"*46,
			"prev": None,
			"type": "plc_operation",
			"services": {},
			"alsoKnownAs": ["B"*TWEAKLEN],
			"rotationKeys": [pubkey_str],
			"verificationMethods": {},
		}
		signed_gensis_template_bytes = cbrrr.encode_dag_cbor(signed_gensis_template)
		template_a, template_remaining = signed_gensis_template_bytes.split(b"A"*46)
		template_b, template_c = template_remaining.split(b"B"*TWEAKLEN)

		k_inv = pow(k, -1, secp256k1.n)
		rDa = (r * private_scalar) % secp256k1.n
		k_inv_rDa = (k_inv * rDa) % secp256k1.n
		lut.append((
			privkey, unsigned_a, unsigned_b, template_a, template_b, template_c, r_bytes_suffix, k_inv_rDa, k_inv
		))

	print(len(unsigned_genesis_bytes))
	print(len(signed_gensis_template_bytes))
	return lut

def mask_last_byte(h: bytes) -> bytes:
	if HASH_END_MASK:
		h = bytearray(h)
		h[-1] &= HASH_END_MASK
		h = bytes(h)
	return h

def sha256_trunc(data: bytes) -> bytes:
	h = hashlib.sha256(data).digest()
	return mask_last_byte(h[:HASH_LENGH_BYTES])

# this fn is in the hot path!
def hash_to_msg(lut, h: bytes) -> bytes:
	privkey, unsigned_a, unsigned_b, template_a, template_b, template_c, r_bytes_suffix, k_inv_rDa, k_inv = lut[h[0]]

	tweak = h[1:].hex().encode()

	z = int.from_bytes(hashlib.sha256(unsigned_a + tweak + unsigned_b).digest(), "big")

	s = ((z * k_inv) + k_inv_rDa) % secp256k1.n
	if s > HALF_N:
		s = secp256k1.n - s

	rawhash_suffix = r_bytes_suffix + s.to_bytes(32, "big")
	rawhash_suffix_b64 = base64.urlsafe_b64encode(rawhash_suffix).rstrip(b"=")

	#assert(len(rawhash_suffix_b64) == 46)

	signed_genesis = template_a + rawhash_suffix_b64 + template_b + tweak + template_c

	#assert(len(signed_genesis) == (4*64 + 55))    # this should later cost 5 invocations of sha256

	return signed_genesis

def pollard_next(lut, h: bytes) -> bytes:
	return sha256_trunc(hash_to_msg(lut, h))

def is_distinguished(h: bytes) -> bool:
	return h.startswith(b"\x00\x00")

def build_trail(lut) -> Tuple[bytes, bytes]:
	trail_start = sha256_trunc(os.urandom(16))
	point = trail_start
	trail_length = 0
	while not is_distinguished(point):
		point = pollard_next(lut, point)
		trail_length += 1
	return trail_start, point, trail_length

def trail_worker(q: Queue, lut):
	while True:
		q.put(build_trail(lut))

def find_collision_point(start_a, start_b):
	# find the point where the two trails meet
	# (naively - time/space tradeoffs are possible here)

	lookup2 = {}
	point = start_a
	while not is_distinguished(point):
		point, prev_a = pollard_next(lut, point), point
		lookup2[point] = prev_a

	point = start_b
	while point not in lookup2:
		point, prev_b = pollard_next(lut, point), point

	return prev_b, lookup2[point]

def do_collision_search(lut):
	q = Queue(100000)
	lookup = {}
	workers = [Process(target=trail_worker, args=(q, lut)) for _ in range(NUM_WORKERS)]
	for w in workers: w.start() # start the workers

	with tqdm(smoothing=0.05, unit_scale=1, unit="plc") as pbar:
		total_iters = 0
		expected_iterations_for_p90 = math.sqrt(math.log(1 - 0.90) * -((2.0**HASH_LENGTH_BITS)*2.0))
		while True:
			start, end, trail_length = q.get()
			if trail_length == 0:  # should be very unlikely but could break things if it happens
				continue

			# update the progress stats:
			total_iters += trail_length

			# https://en.wikipedia.org/wiki/Birthday_problem#Approximations
			success_probability_now = 1-math.e**-((total_iters**2.0)/((2.0**HASH_LENGTH_BITS)*2.0))

			# What percentage of the way are we to reaching 90% odds of success?
			# NOTE: this may be >100%!
			p90_progress = total_iters / expected_iterations_for_p90

			# NOTE: can go negative!
			p90_remaining_iters = expected_iterations_for_p90 - total_iters
			p90_eta = p90_remaining_iters / (pbar.format_dict.get("rate") or 0.1)

			pbar.set_postfix_str(f"prob {success_probability_now*100:.2f}%, p90 progress {p90_progress*100:.2f}% ({'-' if p90_eta < 0 else ''}{tqdm.format_interval(abs(p90_eta))} until p90)", refresh=False)
			pbar.update(trail_length)

			# actually check for a collision
			if end in lookup:
				h_a, h_b = find_collision_point(start, lookup[end])
				if h_a[0] == h_b[0]:
					print("\nyou got unlucky and both DIDs had the same privkey. continuing...")
					continue
				break

			lookup[end] = start

	print(f"Found colliding trails! ({len(lookup)} trails, {total_iters} iterations total)")

	for w in workers: w.kill() # we're done with them now!

	assert(h_a[0] != h_b[0]) # same privkeys

	msg_a = hash_to_msg(lut, h_a)
	msg_b = hash_to_msg(lut, h_b)
	print(f"sha256_{HASH_LENGTH_BITS}({msg_a}) => {sha256_trunc(msg_a).hex()}")
	print(f"sha256_{HASH_LENGTH_BITS}({msg_b}) => {sha256_trunc(msg_b).hex()}")

	plc_a = base64.b32encode(hashlib.sha256(msg_a).digest()[:15]).lower().decode()
	plc_b = base64.b32encode(hashlib.sha256(msg_b).digest()[:15]).lower().decode()
	print("did:plc:" + plc_a)
	print("did:plc:" + plc_b)

	genesis_a = cbrrr.decode_dag_cbor(msg_a)
	genesis_b = cbrrr.decode_dag_cbor(msg_b)

	with open(f"collision_genesis_{plc_a}.json", "w") as outfile:
		json.dump(genesis_a, outfile, indent=4)
	
	with open(f"collision_genesis_{plc_b}.json", "w") as outfile:
		json.dump(genesis_b, outfile, indent=4)

	privkey_a = lut[h_a[0]][0]
	privkey_b = lut[h_b[0]][0]
	util.save_privkey(f"rotationkey_{plc_a}.pem", privkey_a)
	util.save_privkey(f"rotationkey_{plc_b}.pem", privkey_b)

if __name__ == "__main__":
	lut = precompute_lut()
	do_collision_search(lut)
