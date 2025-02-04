package org.bouncycastle.crypto.digests;

/*-
 * ╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲
 * SNMP Java Client
 * ჻჻჻჻჻჻
 * Copyright 2023 Sentry Software, Westhawk
 * ჻჻჻჻჻჻
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 *
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * ╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱
 */

/**
 * Implementation of SHA-256 as outlined in "FIPS PUB 180-4".
 */
public class SHA256Digest extends GeneralDigest {

    private static final int DIGEST_LENGTH = 32;

    // SHA-256 Constants (First 32 bits of fractional parts of square roots of first 8 primes)
    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // SHA-256 Initial Hash Values
    private int H1, H2, H3, H4, H5, H6, H7, H8;
    private int[] W = new int[64];
    private int wOff;

    public SHA256Digest() {
        reset();
    }

    @Override
    public String getAlgorithmName() {
        return "SHA-256";
    }

    @Override
    public int getDigestSize() {
        return DIGEST_LENGTH;
    }

    /** Loads a 4-byte word from the input buffer into W */
    @Override
    protected void processWord(byte[] in, int inOff) {
        W[wOff++] = ((in[inOff] & 0xff) << 24) | ((in[inOff + 1] & 0xff) << 16)
                  | ((in[inOff + 2] & 0xff) << 8) | ((in[inOff + 3] & 0xff));

        if (wOff == 16) {
            processBlock();
        }
    }

    /** Converts an int to 4 bytes */
    private void unpackWord(int word, byte[] out, int outOff) {
        out[outOff]     = (byte) (word >>> 24);
        out[outOff + 1] = (byte) (word >>> 16);
        out[outOff + 2] = (byte) (word >>> 8);
        out[outOff + 3] = (byte) word;
    }

    /** Adds the total message length in bits to W */
    @Override
    protected void processLength(long bitLength) {
        if (wOff > 14) {
            processBlock();
        }
        W[14] = (int) (bitLength >>> 32);
        W[15] = (int) (bitLength & 0xffffffff);
    }

    /** SHA-256 core transformation */
    @Override
    protected void processBlock() {
        // Expand the first 16 words into the remaining 48 words of W
        for (int t = 16; t < 64; t++) {
            int s0 = Integer.rotateRight(W[t - 15], 7) ^ Integer.rotateRight(W[t - 15], 18) ^ (W[t - 15] >>> 3);
            int s1 = Integer.rotateRight(W[t - 2], 17) ^ Integer.rotateRight(W[t - 2], 19) ^ (W[t - 2] >>> 10);
            W[t] = W[t - 16] + s0 + W[t - 7] + s1;
        }

        // Initialize working variables with current hash values
        int a = H1, b = H2, c = H3, d = H4, e = H5, f = H6, g = H7, h = H8;

        // Perform main hash computation
        for (int t = 0; t < 64; t++) {
            int S1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
            int ch = (e & f) ^ (~e & g);
            int temp1 = h + S1 + ch + K[t] + W[t];
            int S0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
            int maj = (a & b) ^ (a & c) ^ (b & c);
            int temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Update hash values
        H1 += a;
        H2 += b;
        H3 += c;
        H4 += d;
        H5 += e;
        H6 += f;
        H7 += g;
        H8 += h;

        // Reset working buffer
        wOff = 0;
        for (int i = 0; i < 16; i++) {
            W[i] = 0;
        }
    }

    /** Finalizes the hash computation */
    @Override
    public int doFinal(byte[] out, int outOff) {
        finish();

        unpackWord(H1, out, outOff);
        unpackWord(H2, out, outOff + 4);
        unpackWord(H3, out, outOff + 8);
        unpackWord(H4, out, outOff + 12);
        unpackWord(H5, out, outOff + 16);
        unpackWord(H6, out, outOff + 20);
        unpackWord(H7, out, outOff + 24);
        unpackWord(H8, out, outOff + 28);

        reset();

        return DIGEST_LENGTH;
    }

    /** Resets the state */
    @Override
    public void reset() {
        super.reset();
        H1 = 0x6A09E667;
        H2 = 0xBB67AE85;
        H3 = 0x3C6EF372;
        H4 = 0xA54FF53A;
        H5 = 0x510E527F;
        H6 = 0x9B05688C;
        H7 = 0x1F83D9AB;
        H8 = 0x5BE0CD19;
        wOff = 0;
        for (int i = 0; i < W.length; i++) {
            W[i] = 0;
        }
    }
}
