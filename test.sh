#!/bin/sh

cd ./native/
make -B mine_nogmp CFLAGS="-DBENCHMARK"
cd ../

# arbitrary, from openssl ecparam -name secp256k1 -genkey -noout
cat > privkey.pem << EOF
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIMJ4L+x/m9+LXqYphlFBTkfeHeiNHdgW2ItS/n1L3vIeoAcGBSuBBAAK
oUQDQgAE3Ey57MyJE8puqkzxkYn6a9meu7jo5oprqSm0x0h1TyCp37nTZ04l0dFx
MBkhPIVJcYPdG+e4w/G2MwP4t/EPow==
-----END EC PRIVATE KEY-----
EOF

python3 native_precompute.py testmode

./native/mine_nogmp 8 ./precomputed.bin \
	"did:key:zQ3shuU4gGmBxEhbf3awc7HgZKaLGsWFsrPR9h8VoayuAsYZd" abcd \
	| tee test_results.txt

rm -f precomputed.bin # prevent accidental reuse

RESULTS_HASH=$(sort test_results.txt | sha256sum | cut -d " " -f1)
rm test_results.txt

echo
echo "Results hash: ${RESULTS_HASH}"

if [ "$RESULTS_HASH" == "1cb290b088aa2ce83ecfd32b68a837aaa4dee41d0000db3c1679d46bbed325eb" ]; then
	echo PASS
else
	echo FAIL
	rm -f privkey.pem  # prevent accidental reuse
	exit
fi

rm -f signed_genesis_abcdreosiqpcxwxszeh64qf5.json # expected output path
python3 native_postcompute.py abcdreosiqpcxwxszeh64qf5 AAAADz 0x4048de9209e53bfa9098deba95fc1948b0c5a341a3b0e1d89124c11124e5c471
GENESIS_HASH=$(sha256sum signed_genesis_abcdreosiqpcxwxszeh64qf5.json | cut -d " " -f1)
#rm -f signed_genesis_abcdreosiqpcxwxszeh64qf5.json

echo
echo "Genesis hash: ${GENESIS_HASH}"

if [ "$GENESIS_HASH" == "25e03279537d05ae3be9b80526d8efb0345c50a64ddd974d9ecdeb3de6ac6c3e" ]; then
	echo PASS
else
	echo FAIL
fi

rm -f privkey.pem  # prevent accidental reuse
