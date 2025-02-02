import requests
import json
import cbrrr
import hashlib
import base64
import sys

def submit_op(path: str):
	op = json.load(open(path))

	plc = base64.b32encode(hashlib.sha256(cbrrr.encode_dag_cbor(op)).digest()[:15]).lower().decode()

	plc_url = f"https://plc.directory/did:plc:{plc}"

	print(f"Submitting {plc_url}...")

	r = requests.post(plc_url, json=op)
	print(r.text)

if __name__ == "__main__":
	for path in sys.argv[1:]:
		submit_op(path)
