// OpenCL kernel for plcmine vanity DID mining
// Ported from mine_nogmp.c / bigint.h / util.h
// SHA-256 adapted from birthday-party/sha256.cl

// Compile-time options (passed via -D):
//   STEPS_PER_TASK   - precomputed table rows each thread processes per call
//   MAX_RESULTS      - max result slots per call
//   NUM_PREFIXES     - number of target prefixes (must match host)

#ifndef STEPS_PER_TASK
#define STEPS_PER_TASK 512
#endif
#ifndef MAX_RESULTS
#define MAX_RESULTS 64
#endif

// Result stride: handle(6) pad(2) row(4) k_inv(32) did_b32(24) = 68
#define RESULT_STRIDE 68

typedef uchar  uint8_t;
typedef uint   uint32_t;
typedef ulong  uint64_t;

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------
constant uint K_SHA[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
constant uint32_t SHA256_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
#define ROTR(x,n) rotate((uint)(x),(uint)(32-(n)))
#define CH(x,y,z)  ((z)^((x)&((y)^(z))))
#define MAJ(x,y,z) (((x)&(y))|((z)&((x)|(y))))
#define EP0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SIG0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SIG1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static void sha256_compress(uint32_t state[8], uint32_t blk[16])
{
    uint a=state[0],b=state[1],c=state[2],d=state[3];
    uint e=state[4],f=state[5],g=state[6],h=state[7];
    #pragma unroll
    for (int i=0;i<16;i++){
        uint t1=h+EP1(e)+CH(e,f,g)+K_SHA[i]+blk[i];
        uint t2=EP0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    #pragma unroll
    for (int i=16;i<64;i++){
        blk[i&15]=SIG1(blk[(i-2)&15])+blk[(i-7)&15]+SIG0(blk[(i-15)&15])+blk[(i-16)&15];
        uint t1=h+EP1(e)+CH(e,f,g)+K_SHA[i]+blk[i&15];
        uint t2=EP0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

// SHA-256 of a byte buffer (any length).
// Writes 32-byte result into out[8] as big-endian uint32s.
static void sha256_buf(const uint8_t *data, uint len, uint32_t out[8])
{
    uint32_t state[8];
    for (int i=0;i<8;i++) state[i]=SHA256_INIT[i];

    uint32_t blk[16];
    uint pos=0;

    // Full 64-byte blocks
    while (pos+64<=len) {
        #pragma unroll
        for (int w=0;w<16;w++) {
            uint b=pos+w*4;
            blk[w]=((uint32_t)data[b]<<24)|((uint32_t)data[b+1]<<16)
                  |((uint32_t)data[b+2]<<8 )|((uint32_t)data[b+3]);
        }
        sha256_compress(state, blk);
        pos+=64;
    }

    // Final partial block
    uint rem=len-pos;
    for (int w=0;w<16;w++) blk[w]=0;
    for (uint b=0;b<rem;b++) {
        uint w=b>>2, sh=24-((b&3)<<3);
        blk[w]|=((uint32_t)data[pos+b])<<sh;
    }
    // Append 0x80 padding byte
    { uint b=rem, w=b>>2, sh=24-((b&3)<<3); blk[w]|=(uint32_t)0x80u<<sh; }

    if (rem<56) {
        blk[15]=len*8;
        sha256_compress(state, blk);
    } else {
        sha256_compress(state, blk);
        for (int w=0;w<16;w++) blk[w]=0;
        blk[15]=len*8;
        sha256_compress(state, blk);
    }
    for (int i=0;i<8;i++) out[i]=state[i];
}

// ---------------------------------------------------------------------------
// 256-bit modular FMA: res = (a*b + c) mod secp256k1_n, then low-s normalization
// Ported from bigint.h (10x26-bit limbs, LSB-first)
// ---------------------------------------------------------------------------
constant uint32_t N_LIMBS[10] = {
    3555649,9937716,33799165,60472610,45788892,
    67108863,67108863,67108863,67108863,4194303
};
constant uint32_t C_LIMBS[5] = { 63553215,57171147,33309698,6636253,21319971 };
#define MASK26 0x03FFFFFFu

static void mod_fma(uint32_t res[10], const uint32_t a[10],
                    const uint32_t b[10], const uint32_t c[10])
{
    uint64_t t[21]; for (int i=0;i<21;i++) t[i]=0;

    for (int i=0;i<10;i++)
        for (int j=0;j<10;j++)
            t[i+j]+=(uint64_t)a[i]*(uint64_t)b[j];

    // First reduction: fold t[10..19] back via C_LIMBS
    uint32_t hi[10]; for (int i=0;i<10;i++) hi[i]=0;
    t[10]+=t[9]>>26; t[9]&=MASK26;
    for (int i=10;i<19;i++){t[i+1]+=t[i]>>26;hi[i-10]=(uint32_t)((t[i]&MASK26)<<4);t[i]=0;}
    hi[9]=(uint32_t)(t[19]<<4);
    for (int i=0;i<10;i++) for (int j=0;j<5;j++) t[i+j]+=(uint64_t)hi[i]*(uint64_t)C_LIMBS[j];

    // Second reduction
    t[10]+=t[9]>>26; t[9]&=MASK26;
    for (int i=10;i<14;i++){t[i+1]+=t[i]>>26;hi[i-10]=(uint32_t)((t[i]&MASK26)<<4);t[i]=0;}
    hi[4]=(uint32_t)(t[14]<<4);
    for (int i=0;i<5;i++) for (int j=0;j<5;j++) t[i+j]+=(uint64_t)hi[i]*(uint64_t)C_LIMBS[j];

    // Add c
    for (int i=0;i<10;i++) t[i]+=c[i];

    // Carry
    for (int i=0;i<10;i++){t[i+1]+=t[i]>>26;t[i]&=MASK26;}

    // Final reduction
    uint32_t ov=(uint32_t)((t[9]>>22)+(t[10]<<4));
    for (int j=0;j<5;j++) t[j]+=(uint64_t)ov*(uint64_t)C_LIMBS[j];
    for (int i=0;i<10;i++){t[i+1]+=t[i]>>26;t[i]&=MASK26;}

    for (int i=0;i<10;i++) res[i]=(uint32_t)t[i];

    // Low-s: if top bit (bit 21 of limb 9) set, res = n - res
    if (res[9]&(1u<<21)){
        for (int i=0;i<10;i++) res[i]=N_LIMBS[i]-res[i];
        for (int i=0;i<9;i++){res[i+1]-=res[i]>>31;res[i]&=MASK26;}
    }
}

// ---------------------------------------------------------------------------
// bigint_unpack: big-endian 32 bytes -> 10x26-bit limbs (LSB-first)
// Copied verbatim from bigint.h
// ---------------------------------------------------------------------------
static void bigint_unpack(uint32_t res[10], const uint8_t buf[32])
{
    res[0]=((uint32_t)buf[31])|((uint32_t)buf[30]<<8)|((uint32_t)buf[29]<<16)|((uint32_t)(buf[28]&0x03)<<24);res[0]&=MASK26;
    res[1]=((uint32_t)(buf[28]>>2))|((uint32_t)buf[27]<<6)|((uint32_t)buf[26]<<14)|((uint32_t)(buf[25]&0x0F)<<22);res[1]&=MASK26;
    res[2]=((uint32_t)(buf[25]>>4))|((uint32_t)buf[24]<<4)|((uint32_t)buf[23]<<12)|((uint32_t)(buf[22]&0x3F)<<20);res[2]&=MASK26;
    res[3]=((uint32_t)(buf[22]>>6))|((uint32_t)buf[21]<<2)|((uint32_t)buf[20]<<10)|((uint32_t)buf[19]<<18);res[3]&=MASK26;
    res[4]=((uint32_t)buf[18])|((uint32_t)buf[17]<<8)|((uint32_t)buf[16]<<16)|((uint32_t)(buf[15]&0x03)<<24);res[4]&=MASK26;
    res[5]=((uint32_t)(buf[15]>>2))|((uint32_t)buf[14]<<6)|((uint32_t)buf[13]<<14)|((uint32_t)(buf[12]&0x0F)<<22);res[5]&=MASK26;
    res[6]=((uint32_t)(buf[12]>>4))|((uint32_t)buf[11]<<4)|((uint32_t)buf[10]<<12)|((uint32_t)(buf[9]&0x3F)<<20);res[6]&=MASK26;
    res[7]=((uint32_t)(buf[9]>>6))|((uint32_t)buf[8]<<2)|((uint32_t)buf[7]<<10)|((uint32_t)buf[6]<<18);res[7]&=MASK26;
    res[8]=((uint32_t)buf[5])|((uint32_t)buf[4]<<8)|((uint32_t)buf[3]<<16)|((uint32_t)(buf[2]&0x03)<<24);res[8]&=MASK26;
    res[9]=((uint32_t)(buf[2]>>2))|((uint32_t)buf[1]<<6)|((uint32_t)buf[0]<<14);res[9]&=0x003FFFFFu;
}

// ---------------------------------------------------------------------------
// bigint_pack: 10x26-bit limbs (LSB-first) -> big-endian 32 bytes
// ---------------------------------------------------------------------------
static void bigint_pack(uint8_t buf[32], const uint32_t b[10])
{
    buf[31]=(b[0]>>0)&0xFF;buf[30]=(b[0]>>8)&0xFF;buf[29]=(b[0]>>16)&0xFF;buf[28]=(b[0]>>24)&0x03;
    buf[28]|=(b[1]&0x3F)<<2;buf[27]=(b[1]>>6)&0xFF;buf[26]=(b[1]>>14)&0xFF;buf[25]=(b[1]>>22)&0x0F;
    buf[25]|=(b[2]&0x0F)<<4;buf[24]=(b[2]>>4)&0xFF;buf[23]=(b[2]>>12)&0xFF;buf[22]=(b[2]>>20)&0x3F;
    buf[22]|=(b[3]&0x03)<<6;buf[21]=(b[3]>>2)&0xFF;buf[20]=(b[3]>>10)&0xFF;buf[19]=(b[3]>>18)&0xFF;
    buf[18]=(b[4]>>0)&0xFF;buf[17]=(b[4]>>8)&0xFF;buf[16]=(b[4]>>16)&0xFF;buf[15]=(b[4]>>24)&0x03;
    buf[15]|=(b[5]&0x3F)<<2;buf[14]=(b[5]>>6)&0xFF;buf[13]=(b[5]>>14)&0xFF;buf[12]=(b[5]>>22)&0x0F;
    buf[12]|=(b[6]&0x0F)<<4;buf[11]=(b[6]>>4)&0xFF;buf[10]=(b[6]>>12)&0xFF;buf[9]=(b[6]>>20)&0x3F;
    buf[9]|=(b[7]&0x03)<<6;buf[8]=(b[7]>>2)&0xFF;buf[7]=(b[7]>>10)&0xFF;buf[6]=(b[7]>>18)&0xFF;
    buf[5]=(b[8]>>0)&0xFF;buf[4]=(b[8]>>8)&0xFF;buf[3]=(b[8]>>16)&0xFF;buf[2]=(b[8]>>24)&0x03;
    buf[2]|=(b[9]&0x3F)<<2;buf[1]=(b[9]>>6)&0xFF;buf[0]=(b[9]>>14)&0xFF;
}

// ---------------------------------------------------------------------------
// Base64 URL-safe no-pad (from util.h)
// ---------------------------------------------------------------------------
constant uint8_t B64[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void b64_encode(uint8_t *out, const uint8_t *data, uint len)
{
    uint i=0;
    while (i+2<len){
        uint8_t a=data[i],b=data[i+1],c=data[i+2]; i+=3;
        *out++=B64[(a>>2)&0x3f];
        *out++=B64[((a<<4)|(b>>4))&0x3f];
        *out++=B64[((b<<2)|(c>>6))&0x3f];
        *out++=B64[c&0x3f];
    }
    if (i+1<len){uint8_t a=data[i],b=data[i+1];*out++=B64[(a>>2)&0x3f];*out++=B64[((a<<4)|(b>>4))&0x3f];*out++=B64[(b<<2)&0x3f];}
    else if (i<len){uint8_t a=data[i];*out++=B64[(a>>2)&0x3f];*out++=B64[(a<<4)&0x3f];}
}

// ---------------------------------------------------------------------------
// Base32 multibase (from util.h)
// charset: abcdefghijklmnopqrstuvwxyz234567
// ---------------------------------------------------------------------------
constant uint8_t B32[32] = "abcdefghijklmnopqrstuvwxyz234567";

// Encode exactly 'len' bytes. Output must have enough room.
static void b32_encode(uint8_t *out, const uint8_t *data, uint len)
{
    uint i=0;
    while (i+4<len){
        uint8_t a=data[i],b=data[i+1],c=data[i+2],d=data[i+3],e=data[i+4]; i+=5;
        *out++=B32[(a>>3)&0x1f];
        *out++=B32[((a<<2)|(b>>6))&0x1f];
        *out++=B32[(b>>1)&0x1f];
        *out++=B32[((b<<4)|(c>>4))&0x1f];
        *out++=B32[((c<<1)|(d>>7))&0x1f];
        *out++=B32[(d>>2)&0x1f];
        *out++=B32[((d<<3)|(e>>5))&0x1f];
        *out++=B32[e&0x1f];
    }
    uint rem=len-i;
    if (rem==4){uint8_t a=data[i],b=data[i+1],c=data[i+2],d=data[i+3];
        *out++=B32[(a>>3)&0x1f];*out++=B32[((a<<2)|(b>>6))&0x1f];
        *out++=B32[(b>>1)&0x1f];*out++=B32[((b<<4)|(c>>4))&0x1f];
        *out++=B32[((c<<1)|(d>>7))&0x1f];*out++=B32[(d>>2)&0x1f];*out++=B32[(d<<3)&0x1f];}
    else if (rem==3){uint8_t a=data[i],b=data[i+1],c=data[i+2];
        *out++=B32[(a>>3)&0x1f];*out++=B32[((a<<2)|(b>>6))&0x1f];
        *out++=B32[(b>>1)&0x1f];*out++=B32[((b<<4)|(c>>4))&0x1f];*out++=B32[(c<<1)&0x1f];}
    else if (rem==2){uint8_t a=data[i],b=data[i+1];
        *out++=B32[(a>>3)&0x1f];*out++=B32[((a<<2)|(b>>6))&0x1f];
        *out++=B32[(b>>1)&0x1f];*out++=B32[(b<<4)&0x1f];}
    else if (rem==1){uint8_t a=data[i];
        *out++=B32[(a>>3)&0x1f];*out++=B32[(a<<2)&0x1f];}
}

// ---------------------------------------------------------------------------
// SHA-256 of signed_op (247 bytes = 4 blocks), built block-by-block without
// a signed_op[256] buffer to avoid private-memory register pressure.
//
// signed_op layout:
//   bytes   0-6:   constant CBOR header  (\xa7csigxV)
//   bytes   7-46:  rb[0..39]             (r_b64, 40 chars)
//   bytes  47-92:  bs[0..45]             (b64_sig, 46 chars)
//   bytes  93-127: constant CBOR mid     (from signed_tpl)
//   bytes 128-191: constant CBOR body    (from signed_tpl, handle at 147-152)
//   bytes 192-246: constant CBOR tail    (from signed_tpl)
// ---------------------------------------------------------------------------
#define PACK4(a,b,c,d) (((uint32_t)(a)<<24)|((uint32_t)(b)<<16)|((uint32_t)(c)<<8)|(uint32_t)(d))

static void sha256_signed_op(
    uint32_t out[8],
    __constant uint8_t *stpl,   // signed_tpl in __constant
    const uint8_t *rb,          // r_b64[40]
    const uint8_t *bs,          // b64_sig[46]
    const uint8_t *handle       // handle[6]
)
{
    uint32_t state[8];
    for (int i=0;i<8;i++) state[i]=SHA256_INIT[i];
    uint32_t blk[16];

    // Block 0: stpl[0..6] + rb[0..39] + bs[0..16]
    blk[0]  = PACK4(stpl[0],  stpl[1],  stpl[2],  stpl[3]);   // \xa7csig
    blk[1]  = PACK4(stpl[4],  stpl[5],  stpl[6],  rb[0]);     // gxV + rb[0]
    blk[2]  = PACK4(rb[1],  rb[2],  rb[3],  rb[4]);
    blk[3]  = PACK4(rb[5],  rb[6],  rb[7],  rb[8]);
    blk[4]  = PACK4(rb[9],  rb[10], rb[11], rb[12]);
    blk[5]  = PACK4(rb[13], rb[14], rb[15], rb[16]);
    blk[6]  = PACK4(rb[17], rb[18], rb[19], rb[20]);
    blk[7]  = PACK4(rb[21], rb[22], rb[23], rb[24]);
    blk[8]  = PACK4(rb[25], rb[26], rb[27], rb[28]);
    blk[9]  = PACK4(rb[29], rb[30], rb[31], rb[32]);
    blk[10] = PACK4(rb[33], rb[34], rb[35], rb[36]);
    blk[11] = PACK4(rb[37], rb[38], rb[39], bs[0]);
    blk[12] = PACK4(bs[1],  bs[2],  bs[3],  bs[4]);
    blk[13] = PACK4(bs[5],  bs[6],  bs[7],  bs[8]);
    blk[14] = PACK4(bs[9],  bs[10], bs[11], bs[12]);
    blk[15] = PACK4(bs[13], bs[14], bs[15], bs[16]);
    sha256_compress(state, blk);

    // Block 1: bs[17..45] + stpl[93..127]
    blk[0]  = PACK4(bs[17], bs[18], bs[19], bs[20]);
    blk[1]  = PACK4(bs[21], bs[22], bs[23], bs[24]);
    blk[2]  = PACK4(bs[25], bs[26], bs[27], bs[28]);
    blk[3]  = PACK4(bs[29], bs[30], bs[31], bs[32]);
    blk[4]  = PACK4(bs[33], bs[34], bs[35], bs[36]);
    blk[5]  = PACK4(bs[37], bs[38], bs[39], bs[40]);
    blk[6]  = PACK4(bs[41], bs[42], bs[43], bs[44]);
    blk[7]  = PACK4(bs[45], stpl[93],  stpl[94],  stpl[95]);
    blk[8]  = PACK4(stpl[96],  stpl[97],  stpl[98],  stpl[99]);
    blk[9]  = PACK4(stpl[100], stpl[101], stpl[102], stpl[103]);
    blk[10] = PACK4(stpl[104], stpl[105], stpl[106], stpl[107]);
    blk[11] = PACK4(stpl[108], stpl[109], stpl[110], stpl[111]);
    blk[12] = PACK4(stpl[112], stpl[113], stpl[114], stpl[115]);
    blk[13] = PACK4(stpl[116], stpl[117], stpl[118], stpl[119]);
    blk[14] = PACK4(stpl[120], stpl[121], stpl[122], stpl[123]);
    blk[15] = PACK4(stpl[124], stpl[125], stpl[126], stpl[127]);
    sha256_compress(state, blk);

    // Block 2: stpl[128..146] + handle[0..5] + stpl[153..191]
    // handle is at signed_op bytes 147-152 (block-local offset 19-24)
    blk[0]  = PACK4(stpl[128], stpl[129], stpl[130], stpl[131]);
    blk[1]  = PACK4(stpl[132], stpl[133], stpl[134], stpl[135]);
    blk[2]  = PACK4(stpl[136], stpl[137], stpl[138], stpl[139]);
    blk[3]  = PACK4(stpl[140], stpl[141], stpl[142], stpl[143]);
    blk[4]  = PACK4(stpl[144], stpl[145], stpl[146], handle[0]);
    blk[5]  = PACK4(handle[1], handle[2], handle[3], handle[4]);
    blk[6]  = PACK4(handle[5], stpl[153], stpl[154], stpl[155]);
    blk[7]  = PACK4(stpl[156], stpl[157], stpl[158], stpl[159]);
    blk[8]  = PACK4(stpl[160], stpl[161], stpl[162], stpl[163]);
    blk[9]  = PACK4(stpl[164], stpl[165], stpl[166], stpl[167]);
    blk[10] = PACK4(stpl[168], stpl[169], stpl[170], stpl[171]);
    blk[11] = PACK4(stpl[172], stpl[173], stpl[174], stpl[175]);
    blk[12] = PACK4(stpl[176], stpl[177], stpl[178], stpl[179]);
    blk[13] = PACK4(stpl[180], stpl[181], stpl[182], stpl[183]);
    blk[14] = PACK4(stpl[184], stpl[185], stpl[186], stpl[187]);
    blk[15] = PACK4(stpl[188], stpl[189], stpl[190], stpl[191]);
    sha256_compress(state, blk);

    // Block 3: stpl[192..246] + 0x80 padding + length (1976 bits)
    blk[0]  = PACK4(stpl[192], stpl[193], stpl[194], stpl[195]);
    blk[1]  = PACK4(stpl[196], stpl[197], stpl[198], stpl[199]);
    blk[2]  = PACK4(stpl[200], stpl[201], stpl[202], stpl[203]);
    blk[3]  = PACK4(stpl[204], stpl[205], stpl[206], stpl[207]);
    blk[4]  = PACK4(stpl[208], stpl[209], stpl[210], stpl[211]);
    blk[5]  = PACK4(stpl[212], stpl[213], stpl[214], stpl[215]);
    blk[6]  = PACK4(stpl[216], stpl[217], stpl[218], stpl[219]);
    blk[7]  = PACK4(stpl[220], stpl[221], stpl[222], stpl[223]);
    blk[8]  = PACK4(stpl[224], stpl[225], stpl[226], stpl[227]);
    blk[9]  = PACK4(stpl[228], stpl[229], stpl[230], stpl[231]);
    blk[10] = PACK4(stpl[232], stpl[233], stpl[234], stpl[235]);
    blk[11] = PACK4(stpl[236], stpl[237], stpl[238], stpl[239]);
    blk[12] = PACK4(stpl[240], stpl[241], stpl[242], stpl[243]);
    blk[13] = PACK4(stpl[244], stpl[245], stpl[246], 0x80);
    blk[14] = 0;
    blk[15] = 247*8;  // 1976 bits
    sha256_compress(state, blk);

    for (int i=0;i<8;i++) out[i]=state[i];
}

// ---------------------------------------------------------------------------
// Main mining kernel
//
// Each work item (gid) handles one handle tweak index (handle_base + gid),
// and processes table rows [row_base, row_base+STEPS_PER_TASK).
//
// presigned_tpl: the unsigned genesis op with pubkey filled, handle=placeholder
// signed_tpl:    the signed genesis op with pubkey filled, sig=placeholder, handle=placeholder
// table:         [num_rows][3][32] = r_bytes || k_inv_rDa_bytes || k_inv_bytes, row-major
// r_b64_tbl:     [num_rows][40]   = first 30 bytes of r base64-encoded (40 chars per row)
// firstbytes:    [num_prefixes]   = expected hash[0] for each prefix (for fast pre-filter)
// prefix_data:   flattened prefix strings (base32 chars, not null-terminated)
// prefix_lens:   [num_prefixes] lengths
// prefix_offsets:[num_prefixes] start indices into prefix_data
// results:       output, RESULT_STRIDE bytes per slot
// result_count:  atomic counter of results found
// handle_base:   first handle index for this kernel call
// row_base:      first table row for this kernel call
// num_rows:      total rows in table
// presigned_len:        byte length of presigned_tpl
// presigned_handle_off: byte offset of 6-char handle in presigned_tpl
// ---------------------------------------------------------------------------
__kernel void mine_plc(
    __constant uint8_t  *presigned_tpl,
    __constant uint8_t  *signed_tpl,
    __global   uint8_t  *table,
    __global   uint8_t  *r_b64_tbl,
    __constant uint8_t  *firstbytes,
    __constant uint8_t  *prefix_data,
    __constant uint32_t *prefix_lens,
    __constant uint32_t *prefix_offsets,
    __global   uint8_t  *results,
    __global volatile uint *result_count,
    const uint32_t handle_base,
    const uint32_t row_base,
    const uint32_t num_rows,
    const uint32_t presigned_len,
    const uint32_t presigned_handle_off,
    const uint32_t num_prefixes
)
{
    uint gid = get_global_id(0);
    uint handle_idx = handle_base + gid;

    // Decode 6-char handle from index (same as mine_nogmp.c)
    uint8_t handle[6];
    {
        uint32_t idx = handle_idx;
        for (int j=0;j<6;j++){ handle[5-j]=B64[idx&0x3f]; idx>>=6; }
    }

    // Build presigned with this handle and SHA256 it to get z
    uint8_t presigned[160];
    for (uint i=0;i<presigned_len;i++) presigned[i]=presigned_tpl[i];
    for (int j=0;j<6;j++) presigned[presigned_handle_off+j]=handle[j];

    uint32_t z_state[8];
    sha256_buf(presigned, presigned_len, z_state);

    uint8_t z_bytes[32];
    for (int w=0;w<8;w++){
        z_bytes[w*4+0]=(z_state[w]>>24)&0xFF; z_bytes[w*4+1]=(z_state[w]>>16)&0xFF;
        z_bytes[w*4+2]=(z_state[w]>> 8)&0xFF; z_bytes[w*4+3]=(z_state[w]    )&0xFF;
    }
    uint32_t z[10];
    bigint_unpack(z, z_bytes);

    uint32_t row_end = row_base + STEPS_PER_TASK;
    if (row_end > num_rows) row_end = num_rows;

    for (uint row=row_base; row<row_end; row++) {
        // Load k_inv_rDa and k_inv from table (each row = 96 bytes: r|k_inv_rDa|k_inv)
        uint tbl = row * 96;
        uint8_t k_inv_rDa_bytes[32], k_inv_bytes[32];
        for (int b=0;b<32;b++){
            k_inv_rDa_bytes[b]=table[tbl+32+b];
            k_inv_bytes[b]    =table[tbl+64+b];
        }
        uint32_t k_inv_rDa[10], k_inv_l[10];
        bigint_unpack(k_inv_rDa, k_inv_rDa_bytes);
        bigint_unpack(k_inv_l,   k_inv_bytes);

        // s = (z * k_inv + k_inv_rDa) mod n  (with low-s)
        uint32_t s[10];
        mod_fma(s, z, k_inv_l, k_inv_rDa);

        uint8_t s_bytes[32];
        bigint_pack(s_bytes, s);

        // Build raw_sig = r_bytes[30..31] || s_bytes[0..31]  (34 bytes)
        uint8_t raw_sig[34];
        raw_sig[0]=table[tbl+30]; raw_sig[1]=table[tbl+31];
        for (int b=0;b<32;b++) raw_sig[2+b]=s_bytes[b];

        // r_b64[40] = precomputed base64 of r_bytes[0..29]
        uint8_t rb[40];
        uint rb64 = row * 40;
        for (int b=0;b<40;b++) rb[b]=r_b64_tbl[rb64+b];

        // b64_sig[46] = base64url_nopad(raw_sig[34])
        uint8_t b64_sig[46];
        b64_encode(b64_sig, raw_sig, 34);

        // DID hash = SHA256(signed_op), built block-by-block without a buffer
        uint32_t did_state[8];
        sha256_signed_op(did_state, signed_tpl, rb, b64_sig, handle);

        // Quick first-byte filter
        uint8_t b0=(did_state[0]>>24)&0xFF;
        int hit=0;
        for (uint p=0;p<num_prefixes;p++) if (b0==firstbytes[p]){hit=1;break;}
        if (!hit) continue;

        // Extract first 15 bytes of DID hash and base32-encode -> 24 chars
        uint8_t did_hash[15];
        for (int b=0;b<15;b++){int w=b/4,sh=24-(b&3)*8;did_hash[b]=(did_state[w]>>sh)&0xFF;}
        uint8_t did_b32[24];
        b32_encode(did_b32, did_hash, 15);

        // Check prefixes
        for (uint p=0;p<num_prefixes;p++){
            if (b0!=firstbytes[p]) continue;
            uint plen=prefix_lens[p], poff=prefix_offsets[p];
            int ok=1;
            for (uint ci=0;ci<plen;ci++) if (did_b32[ci]!=prefix_data[poff+ci]){ok=0;break;}
            if (!ok) continue;

            uint slot=atomic_inc(result_count);
            if (slot<MAX_RESULTS){
                uint roff=slot*RESULT_STRIDE;
                // handle (6), pad (2), row (4), k_inv (32), did_b32 (24)
                for (int b=0;b<6;b++) results[roff+b]=handle[b];
                results[roff+6]=0; results[roff+7]=0; // pad
                results[roff+8]=(row>>24)&0xFF; results[roff+9]=(row>>16)&0xFF;
                results[roff+10]=(row>>8)&0xFF;  results[roff+11]=row&0xFF;
                for (int b=0;b<32;b++) results[roff+12+b]=k_inv_bytes[b];
                for (int b=0;b<24;b++) results[roff+44+b]=did_b32[b];
            }
        }
    }
}
