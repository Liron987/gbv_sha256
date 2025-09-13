#pragma once

typedef struct 
{
    u8 gvv[32];
} 
GibuvSHA256;
// קבועים מעוגלים הנוצרים במהלך קבלת הערכים של השורשים המרובעים של 8 מספרים ראשוניים
// 2, 3, 5, 7, 11, 13, 17, 19
static const u32 meuglim[] = 
{
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

u32 rotr(u32 x, u32 n) {
    return (x >> n) | (x << (32 - n));
}

GibuvSHA256 sha256(const char *hruz)
{
    GibuvSHA256 gibuv = { 0 };
    // שורשים ריבועיים של מספרים ראשוניים שנבחרו: 2, 3, 5, 7, 11, 13, 17, 19
    u32 srms[] =
    {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // אורך החרוז בביטים
    size_t orc_hruz = strlen(hruz);
    size_t orc_bitim = orc_hruz * 8;
    // הוספת ביט אחד 0x80 (128) לאורך הכולל
    size_t orc = orc_bitim + 1;
    // הוספת ביטים של 0 עד שמגיעים לאורך של 448 % 512 כלומר נשאר 64 ביטים
    // שהם 8 בייטים (512 - 448 = 64)
    size_t orc_ripud_afsim = ( (orc + 511 - 448) / 512) * 512 + 448;
    // להוסיף 64 ביטים לקידוד אורך ההודעה המקורית
    orc_ripud_afsim += 64;
    // המרת האורך לבייטים
    size_t orc_ripud_bytim = orc_ripud_afsim / 8;

    Vec zmni = 
    { 
        .mt = calloc(orc_ripud_bytim, 1),
        .orc = orc_ripud_bytim
    };

    memcpy(zmni.mt, hruz, orc_hruz);
    zmni.mt[orc_hruz] = 0x80;
    // נכתוב את האורך חרוז המקורי אל ה-8 בייטים האחרונים
    u64 orc_mkori_bitim = orc_hruz * 8;
    for (int h = 0; h < 8; h++) 
        zmni.mt[orc_ripud_bytim - 1 - h] = (orc_mkori_bitim >> (h * 8) ) & 0xff;



    for (size_t mirvh = 0; mirvh < zmni.orc; mirvh += 64) 
    {
        u32 W[64] = { 0 };

        // Step 1: Prepare the first 16 words (32-bit each) from the chunk
        for (int i = 0; i < 16; i++) {
                W[i] = ((u32)zmni.mt[mirvh + i * 4] << 24) |
                        ((u32)zmni.mt[mirvh + i * 4 + 1] << 16) |
                        ((u32)zmni.mt[mirvh + i * 4 + 2] << 8) |
                        ((u32)zmni.mt[mirvh + i * 4 + 3]);
        }

        // Step 2: Extend the remaining 48 words
        for (int i = 16; i < 64; i++) {
            u32 s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
            u32 s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
            W[i] = W[i - 16] + s0 + W[i - 7] + s1;
        }

        // Step 3: Initialize working variables with current hash state
        u32 a = srms[0], b = srms[1], c = srms[2], 
            d = srms[3];
        u32 e = srms[4], f = srms[5], g = srms[6], 
            h = srms[7];

        // Step 4: Compression loop
        for (int i = 0; i < 64; i++) {
            u32 S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            u32 ch = (e & f) ^ (~e & g);
            u32 temp1 = h + S1 + ch + meuglim[i] + W[i];
            u32 S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            u32 maj = (a & b) ^ (a & c) ^ (b & c);
            u32 temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Step 5: Add compressed chunk to current hash value
        srms[0] += a; srms[1] += b; srms[2] += c; srms[3] += d;
        srms[4] += e; srms[5] += f; srms[6] += g; srms[7] += h;
    }

    // לסיום, נעתיק את מעמדי הגיבוב (srms) לתוך הגיבוב הסופי (קצה-גדול big-endian)
    for (int i = 0; i < 8; i++) {
        gibuv.gvv[i * 4 + 0] = (srms[i] >> 24) & 0xff;
        gibuv.gvv[i * 4 + 1] = (srms[i] >> 16) & 0xff;
        gibuv.gvv[i * 4 + 2] = (srms[i] >>  8) & 0xff;
        gibuv.gvv[i * 4 + 3] = (srms[i] >>  0) & 0xff;
    }

    free(zmni.mt);
    
    return gibuv;
}