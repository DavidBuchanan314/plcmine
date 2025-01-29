# plcmine
Yet another vanity [did:plc](https://github.com/did-method-plc/did-method-plc) miner (GMP+OpenSSL on CPU, for now - might port to OpenCL one day)

## How fast does it go?

~56 million DIDs per second on my 3950x, using 32 threads.

## How does it work?

We precompute the "first half" of secp256k1 ECDSA signing, for a few thousand different values of `k`, and store them in a lookup table. This part is implemented in pure python, and only takes a couple of seconds to run.

Then, in optimised-ish native code, we generate a `did:plc` genesis operation, hash it (deriving `z`), and then compute the full ECDSA signature for each entry in our lookup table. Because of the precomputation, the only math required in the inner loop is a single 256-bit addition followed by a 256-bit modular multiplication. We compute the resulting base32 `did:plc` string (which involves SHA256 hashing the signed genesis operation), and print it out if it matches the prefix we're searching for.

Note to self: we can rearrange things so the multiplication happens before the addition, might help with carry logic when moving to a GPU impl.

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

TODO (tl;dr keygen, precompute, mine, postcompute)
