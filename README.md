# plcmine
Yet another vanity [did:plc](https://github.com/did-method-plc/did-method-plc) miner (GMP+OpenSSL on CPU, for now - might port to OpenCL one day)

See also https://github.com/katietheqt/vanity-did-plc, which uses a slightly different mining strategy. I haven't benchmarked the two, but I believe plcmine should be marginally slower, but more secure since it doesn't involve publishing any ops with weak private keys - the signatures it generates are "real". The  simple-ish arithmetic used in the inner loop of plcmine should make it amenable to a GPU implementation if I get around to that.

(Edit: I did benchmark the two. While in principle vanity-did-plc should be a bit faster than plcmine due to even simpler arithmetic in the inner loop (iiuc), in practice it's about 1.5x slower on my machine, for whatever reason.)

## How fast does it go?

~56 million DIDs per second on my 3950x, using 32 threads.

(Edit: `mine_nogmp` now goes at 99M/sec, using optimized bigint routines. Build it with `make mine_nogmp` - I'll make it the default in the future.)

## How does it work?

We precompute the "first half" of secp256k1 ECDSA signing, for a few thousand different values of `k`, and store them in a lookup table. This part is implemented in pure python, and only takes a couple of seconds to run.

Then, in optimised-ish native code, we generate a `did:plc` genesis operation, hash it (deriving `z`), and then compute the full ECDSA signature for each entry in our lookup table. Because of the precomputation, the only math required in the inner loop is a single 256-bit multiplication followed by a 256-bit addition (both modulo `n`). We compute the resulting base32 `did:plc` string (which involves SHA256 hashing the signed genesis operation), and print it out if it matches the prefix we're searching for.

So the speed of the inner loop mostly comes down to:

- A single 256-bit modular multiplication (modulo the secp256k1 group order, aka `n`) (we use GNU GMP for this)
- A 4-block SHA-256 hash calculation (over a message of length 247 bytes) (we use OpenSSL with the DePrEcAtEd API, which is [significantly faster](https://github.com/openssl/openssl/issues/19612) than the not-deprecated EVP API for short messages)

Once we've run out of lookup table entries, we tweak the genesis operation (changing the `at://` handle string) to give a different hash/`z` value, and repeat the process from there.

Finally, the "postcompute" python script takes a line of output from the miner and turns it into a JSON object for submission to plc.directory.

> [!CAUTION]
> VERY IMPORTANT: The mining script will print out multiple matches, until you stop. It is only safe to publish **ONE** of them, for a given precomputation table. If you want to generate and publish multiple DIDs, you **MUST** re-run the precomputation phase between each mining session (and probably generate a fresh private key, too).
>
> In general, I cannot vouch for the security of DIDs mined using this code - it's the scary hand-rolled crypto they warned you about. You can mitigate this by performing a `did:plc` key rotation operation, to swap in a fresh key (but even then, you're relying on the honesty of `plc.directory` to keep your account safe).

## How do I use it?

tl;dr keygen, precompute, mine, postcompute

```sh
# install python deps
python3 -m pip install -r requirements.txt

# compile native miner
cd ./native/
make mine_nogmp
cd ../

# keygen
openssl ecparam -name secp256k1 -genkey -noout -out privkey.pem

# precompute
python3 native_precompute.py
# example output:
# precomputed tables for DID pubkey:
# did:key:zQ3shiRNWQ9vbuRcDoNPjhVTe92r1sEe9MWyvjkLJCNgoSydq

# mine
# (tweak the number of threads to suit your hardware)
$ ./native/mine_nogmp 8 precomputed.bin 'did:key:zQ3shiRNWQ9vbuRcDoNPjhVTe92r1sEe9MWyvjkLJCNgoSydq' 'hello'
imported 100000 rows, running on 8 threads
hellonh6tnqquf4ygt5zueh6 YAAAAY 0x65d4e0b1e7573f384bcb401e3c1fa914e26fdeb9c9a9c11b7215475b0abcdf1b
helloggijh7mpx5oeqhedymo oAAAAy 0x58cbc33d23b94e45bd3682a645c829c8e9229f7170d58f219e1642b367a8b876
helloe4b2nvugmjeqva6ek7n QAAADz 0x448ba85adaa53dd88ba5b58d2bd6af830e0f60a618b46b8abbaf435f03e3edb
hello3rh2nclstbeukh4sebh YAAAEL 0x5e0c50a735bd2e990df0797e5507778ef0283680f009f7f9e6454ae7bca6d6cf
...
^C

# select the one you want
python3 native_postcompute.py helloggijh7mpx5oeqhedymo oAAAAy 0x58cbc33d23b94e45bd3682a645c829c8e9229f7170d58f219e1642b367a8b876
# example output:
# your signed genesis op is at 'signed_genesis_helloggijh7mpx5oeqhedymo.json' and ready to be published

# submit to plc.directory
curl --json @signed_genesis_helloggijh7mpx5oeqhedymo.json "https://plc.directory/did:plc:helloggijh7mpx5oeqhedymo"
```

> [!CAUTION]
> The log lines output from the `mine` step are cryptographically sensitive. Do not share them! Same goes for the `precomputed.bin` file.
