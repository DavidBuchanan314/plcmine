#!/usr/bin/env python3
"""
OpenCL vanity DID miner for plcmine.
Drop-in replacement for native/mine_nogmp, using GPU via PyOpenCL.

Usage:
    python3 ocl_mine.py precomputed.bin did:key:<pubkey> <prefix> [prefix2 ...]

Output format (same as mine_nogmp):
    <did_b32> <handle> 0x<k_inv_hex>
"""

import os
import sys
import time
import argparse

import numpy as np
import pyopencl as cl

# ---------------------------------------------------------------------------
# Constants matching the kernel and mine_nogmp.c
# ---------------------------------------------------------------------------
WORK_SIZE      = 0x100000   # GPU threads per call (handles per batch)
STEPS_PER_TASK = 512      # Table rows each thread processes per call
MAX_RESULTS    = 64
RESULT_STRIDE  = 68       # bytes per result slot: handle(6)+pad(2)+row(4)+k_inv(32)+did_b32(24)

B32_CHARSET = b"abcdefghijklmnopqrstuvwxyz234567"

# ---------------------------------------------------------------------------
# Template construction
# ---------------------------------------------------------------------------
# presigned CBOR template (matching mine_nogmp.c line 75):
# \xa6 dprev \xf6 dtype mplc_operation hservices \xa0
# kalsoKnownAs \x81 kat:// HANDLE lrotationKeys \x81 x9 PUBKEY
# sverificationMethods \xa0
#
# Byte offsets (verified against mine_nogmp.c):
#   HANDLE at 55, PUBKEY at 77, total length 155

PRESIGNED_HANDLE_OFF = 55
PRESIGNED_PUBKEY_OFF = 77
PRESIGNED_LEN = 155

SIGNED_SIG_OFF    = 7
SIGNED_HANDLE_OFF = 147
SIGNED_PUBKEY_OFF = 169
SIGNED_LEN = 247   # sizeof(signed_op)-1 in mine_nogmp.c


def build_presigned_template(pubkey: str) -> bytes:
    """
    Build the presigned (unsigned genesis op) template with pubkey filled and handle zeroed.
    Uses the same format string as mine_nogmp.c line 75, with handle placeholder 'AAAAAA'.
    """
    assert len(pubkey) == 57, f"pubkey must be 57 chars (got {len(pubkey)})"
    # Exact format string from mine_nogmp.c snprintf call, with handle='AAAAAA'
    tpl = (
        b"\xa6dprev\xf6dtypemplc_operationhservices\xa0"
        b"kalsoKnownAs\x81kat://AAAAAAlrotationKeys\x81x9"
        + pubkey.encode()
        + b"sverificationMethods\xa0"
    )
    assert len(tpl) == PRESIGNED_LEN, f"presigned length mismatch: {len(tpl)} != {PRESIGNED_LEN}"
    return tpl


def build_signed_template(pubkey: str) -> bytes:
    """
    Build the signed genesis op template with pubkey filled, sig and handle as placeholders.
    Uses the same byte string as mine_nogmp.c's signed_op[], with pubkey replaced.
    """
    assert len(pubkey) == 57, f"pubkey must be 57 chars (got {len(pubkey)})"
    # Exact bytes from mine_nogmp.c signed_op[] with pubkey slot zeroed, then filled.
    # sig placeholder = 86 'A's; handle placeholder = 'AAAAAA'; pubkey filled from arg.
    tpl = bytearray(
        b"\xa7csigxV"
        + b"A" * 86
        + b"dprev\xf6dtypemplc_operationhservices\xa0"
        b"kalsoKnownAs\x81kat://AAAAAAlrotationKeys\x81x9"
        + b"X" * 57   # pubkey placeholder, filled below
        + b"sverificationMethods\xa0"
    )
    tpl[SIGNED_PUBKEY_OFF : SIGNED_PUBKEY_OFF + 57] = pubkey.encode()
    tpl = bytes(tpl)
    assert len(tpl) == SIGNED_LEN, f"signed length mismatch: {len(tpl)} != {SIGNED_LEN}"
    return tpl


# ---------------------------------------------------------------------------
# Prefix helpers (matching mine_nogmp.c)
# ---------------------------------------------------------------------------

def prefix_firstbyte(prefix: str) -> int:
    """Compute the expected first byte of SHA256(signed_op) for a given base32 prefix."""
    cs = B32_CHARSET
    c0 = cs.index(prefix[0].encode()[0])
    c1 = cs.index(prefix[1].encode()[0])
    return (c0 << 3) | (c1 >> 2)


def build_prefix_buffers(prefixes: list[str]):
    """
    Returns (firstbytes, prefix_data, prefix_lens, prefix_offsets) as numpy arrays.
    """
    firstbytes = np.array([prefix_firstbyte(p) for p in prefixes], dtype=np.uint8)
    flat = b"".join(p.encode() for p in prefixes)
    prefix_data = np.frombuffer(flat, dtype=np.uint8).copy()
    prefix_lens = np.array([len(p) for p in prefixes], dtype=np.uint32)
    offsets = np.zeros(len(prefixes), dtype=np.uint32)
    off = 0
    for i, p in enumerate(prefixes):
        offsets[i] = off
        off += len(p)
    return firstbytes, prefix_data, prefix_lens, offsets


# ---------------------------------------------------------------------------
# Precomputed table helpers
# ---------------------------------------------------------------------------

MASK26 = 0x03FFFFFF

def bigint_unpack(buf: bytes) -> list[int]:
    """Unpack 32 big-endian bytes into 10x26-bit limbs (LSB-first). Matches ocl_mine.cl."""
    r = [0] * 10
    r[0] = buf[31] | (buf[30]<<8) | (buf[29]<<16) | ((buf[28]&0x03)<<24); r[0] &= MASK26
    r[1] = (buf[28]>>2) | (buf[27]<<6) | (buf[26]<<14) | ((buf[25]&0x0F)<<22); r[1] &= MASK26
    r[2] = (buf[25]>>4) | (buf[24]<<4) | (buf[23]<<12) | ((buf[22]&0x3F)<<20); r[2] &= MASK26
    r[3] = (buf[22]>>6) | (buf[21]<<2) | (buf[20]<<10) | (buf[19]<<18); r[3] &= MASK26
    r[4] = buf[18] | (buf[17]<<8) | (buf[16]<<16) | ((buf[15]&0x03)<<24); r[4] &= MASK26
    r[5] = (buf[15]>>2) | (buf[14]<<6) | (buf[13]<<14) | ((buf[12]&0x0F)<<22); r[5] &= MASK26
    r[6] = (buf[12]>>4) | (buf[11]<<4) | (buf[10]<<12) | ((buf[9]&0x3F)<<20); r[6] &= MASK26
    r[7] = (buf[9]>>6) | (buf[8]<<2) | (buf[7]<<10) | (buf[6]<<18); r[7] &= MASK26
    r[8] = buf[5] | (buf[4]<<8) | (buf[3]<<16) | ((buf[2]&0x03)<<24); r[8] &= MASK26
    r[9] = (buf[2]>>2) | (buf[1]<<6) | (buf[0]<<14); r[9] &= 0x003FFFFF
    return r


def load_precomputed(path: str):
    """
    Load precomputed.bin -> (limb_table, r_b64_table, r_tail, num_rows).

    limb_table: [num_rows * 20] uint32 = k_inv_rDa(10 limbs) || k_inv(10 limbs) per row.
    r_b64_table: [num_rows * 40] uint8 = base64(r[0:30]) per row.
    r_tail:      [num_rows * 2] uint8 = r_bytes[30..31] per row.
    """
    with open(path, "rb") as f:
        raw = f.read()
    row_size = 96  # 3 * 32
    assert len(raw) % row_size == 0
    num_rows = len(raw) // row_size

    # Pre-unpack k_inv_rDa and k_inv into 26-bit limbs
    limb_table = np.zeros(num_rows * 20, dtype=np.uint32)
    r_tail = np.zeros(num_rows * 2, dtype=np.uint8)
    for i in range(num_rows):
        base = i * 96
        k_inv_rDa_bytes = raw[base+32 : base+64]
        k_inv_bytes     = raw[base+64 : base+96]
        limb_table[i*20 : i*20+10] = bigint_unpack(k_inv_rDa_bytes)
        limb_table[i*20+10 : i*20+20] = bigint_unpack(k_inv_bytes)
        r_tail[i*2]   = raw[base+30]
        r_tail[i*2+1] = raw[base+31]

    # Precompute r_b64: for each row, base64-encode r_bytes[0:30]
    import base64
    r_b64 = bytearray(num_rows * 40)
    for i in range(num_rows):
        r_bytes = raw[i*96 : i*96+30]  # first 30 bytes of r
        # base64 url-safe no-pad of 30 bytes -> 40 chars
        enc = base64.b64encode(r_bytes, altchars=b"-_").rstrip(b"=")
        assert len(enc) == 40, f"r_b64 length {len(enc)} != 40"
        r_b64[i*40 : (i+1)*40] = enc

    r_b64_arr = np.frombuffer(r_b64, dtype=np.uint8).copy()
    return limb_table, r_b64_arr, r_tail, num_rows


# ---------------------------------------------------------------------------
# OpenCL miner class
# ---------------------------------------------------------------------------

class PLCMiner:
    def __init__(self, limb_table: np.ndarray, r_b64_tbl: np.ndarray,
                 r_tail: np.ndarray, num_rows: int,
                 presigned_tpl: bytes, signed_tpl: bytes,
                 prefixes: list[str],
                 work_size: int = WORK_SIZE,
                 steps_per_task: int = STEPS_PER_TASK):
        self.num_rows = num_rows
        self.work_size = work_size
        self.steps_per_task = steps_per_task
        self.num_prefixes = len(prefixes)

        ctx = cl.create_some_context()
        self.ctx = ctx
        self.queue = cl.CommandQueue(ctx)

        RO = cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR

        # Large read-only buffers (global memory)
        self.limb_table_buf = cl.Buffer(ctx, RO, hostbuf=limb_table)
        self.r_b64_buf      = cl.Buffer(ctx, RO, hostbuf=r_b64_tbl)
        self.r_tail_buf     = cl.Buffer(ctx, RO, hostbuf=r_tail)

        # Small constant buffers
        presigned_np = np.frombuffer(presigned_tpl, dtype=np.uint8)
        signed_np    = np.frombuffer(signed_tpl,    dtype=np.uint8)
        self.presigned_buf = cl.Buffer(ctx, RO, hostbuf=presigned_np)
        self.signed_buf    = cl.Buffer(ctx, RO, hostbuf=signed_np)

        firstbytes, prefix_data, prefix_lens, prefix_offsets = build_prefix_buffers(prefixes)
        self.firstbytes_buf    = cl.Buffer(ctx, RO, hostbuf=firstbytes)
        self.prefix_data_buf   = cl.Buffer(ctx, RO, hostbuf=prefix_data)
        self.prefix_lens_buf   = cl.Buffer(ctx, RO, hostbuf=prefix_lens)
        self.prefix_offsets_buf= cl.Buffer(ctx, RO, hostbuf=prefix_offsets)

        # Result buffers
        self.results     = np.zeros(MAX_RESULTS * RESULT_STRIDE, dtype=np.uint8)
        self.result_count= np.zeros(1, dtype=np.uint32)
        self.results_buf     = cl.Buffer(ctx, cl.mem_flags.READ_WRITE, size=self.results.nbytes)
        self.result_count_buf= cl.Buffer(ctx, cl.mem_flags.READ_WRITE, size=self.result_count.nbytes)

        # Compile kernel
        srcdir = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(srcdir, "ocl_mine.cl")) as f:
            src = f.read()
        opts = (f"-DSTEPS_PER_TASK={steps_per_task} -DMAX_RESULTS={MAX_RESULTS}"
                f" -DPRESIGNED_LEN={PRESIGNED_LEN} -DSIGNED_LEN={SIGNED_LEN}"
                f" -DPRESIGNED_HANDLE_OFF={PRESIGNED_HANDLE_OFF}"
                f" -DSIGNED_SIG_OFF={SIGNED_SIG_OFF}"
                f" -DSIGNED_HANDLE_OFF={SIGNED_HANDLE_OFF}")
        prg = cl.Program(ctx, src).build(options=opts)
        self.kernel = cl.Kernel(prg, "mine_plc")

    def mine_batch(self, handle_base: int, row_base: int) -> list[dict]:
        """
        Run one kernel call: work_size handles × STEPS_PER_TASK rows.
        Returns list of result dicts: {handle, row, k_inv_bytes, did_b32}.
        """
        self.result_count[0] = 0
        cl.enqueue_copy(self.queue, self.result_count_buf, self.result_count)

        args = [
            self.presigned_buf,
            self.signed_buf,
            self.limb_table_buf,
            self.r_b64_buf,
            self.r_tail_buf,
            self.firstbytes_buf,
            self.prefix_data_buf,
            self.prefix_lens_buf,
            self.prefix_offsets_buf,
            self.results_buf,
            self.result_count_buf,
            np.uint32(handle_base),
            np.uint32(row_base),
            np.uint32(self.num_rows),
            np.uint32(self.num_prefixes),
        ]
        self.kernel(self.queue, (self.work_size,), None, *args)

        cl.enqueue_copy(self.queue, self.result_count, self.result_count_buf)
        self.queue.finish()

        n = min(int(self.result_count[0]), MAX_RESULTS)
        if n == 0:
            return []

        cl.enqueue_copy(self.queue, self.results, self.results_buf)
        self.queue.finish()

        found = []
        for i in range(n):
            off = i * RESULT_STRIDE
            handle   = bytes(self.results[off:off+6])
            row      = int.from_bytes(self.results[off+8:off+12], "big")
            k_inv    = bytes(self.results[off+12:off+44])
            did_b32  = bytes(self.results[off+44:off+68])
            found.append({"handle": handle, "row": row,
                          "k_inv": k_inv, "did_b32": did_b32})
        return found


# ---------------------------------------------------------------------------
# Mining loop
# ---------------------------------------------------------------------------

def run(precomputed_path: str, pubkey: str, prefixes: list[str],
        work_size: int = WORK_SIZE, steps_per_task: int = STEPS_PER_TASK):

    # Validate
    if len(pubkey) != 57:
        sys.exit("pubkey must be 57 chars including did:key: prefix")
    for p in prefixes:
        if len(p) < 2:
            sys.exit(f"prefix '{p}' must be at least 2 chars")
        if len(p) > 8:
            sys.exit(f"prefix '{p}' longer than 8 chars not supported (grep the output?)")

    print(f"Loading precomputed table from {precomputed_path}...", file=sys.stderr)
    limb_table, r_b64_tbl, r_tail, num_rows = load_precomputed(precomputed_path)
    print(f"Loaded {num_rows} rows.", file=sys.stderr)

    presigned_tpl = build_presigned_template(pubkey)
    signed_tpl    = build_signed_template(pubkey)

    print("Initializing OpenCL...", file=sys.stderr)
    miner = PLCMiner(limb_table, r_b64_tbl, r_tail, num_rows, presigned_tpl, signed_tpl,
                     prefixes, work_size=work_size, steps_per_task=steps_per_task)
    print("Ready. Mining...", file=sys.stderr)

    total_plcs = 0
    total_found = 0
    start_time = time.time()
    handle_base = 0

    try:
        while True:
            for row_base in range(0, num_rows, steps_per_task):
                found = miner.mine_batch(handle_base, row_base)

                rows_this_call = min(steps_per_task, num_rows - row_base)
                plcs_this_call = work_size * rows_this_call
                total_plcs += plcs_this_call

                for r in found:
                    total_found += 1
                    handle_str = r["handle"].decode("ascii")
                    k_inv_hex  = r["k_inv"].hex()
                    did_b32    = r["did_b32"].decode("ascii")
                    print(f"{did_b32} {handle_str} 0x{k_inv_hex}")
                    sys.stdout.flush()

                duration = time.time() - start_time
                rate = total_plcs / 1e6 / duration if duration > 0 else 0
                print(
                    f"\t Stats: {total_plcs:,} PLCs in {duration:.1f}s "
                    f"({rate:.1f}M/s avg) Found: {total_found}\r",
                    end="", file=sys.stderr
                )

            handle_base += work_size

    except KeyboardInterrupt:
        duration = time.time() - start_time
        print(file=sys.stderr)
        print(f"Stopped. {total_plcs:,} PLCs in {duration:.1f}s, found {total_found}.",
              file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="OpenCL plcmine vanity DID miner (GPU port of mine_nogmp)"
    )
    parser.add_argument("precomputed", help="Path to precomputed.bin")
    parser.add_argument("pubkey", help="did:key:... public key (57 chars)")
    parser.add_argument("prefixes", nargs="+", help="Target DID prefixes (base32)")
    parser.add_argument("--work-size", type=int, default=WORK_SIZE,
                        help=f"GPU work size (default: {WORK_SIZE})")
    parser.add_argument("--steps", type=int, default=STEPS_PER_TASK,
                        help=f"Table rows per thread per call (default: {STEPS_PER_TASK})")
    args = parser.parse_args()
    run(args.precomputed, args.pubkey, args.prefixes,
        work_size=args.work_size, steps_per_task=args.steps)


if __name__ == "__main__":
    main()
