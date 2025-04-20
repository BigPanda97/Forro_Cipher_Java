/**
 * Self-contained (no imports) implementation of the Forró stream cipher **and**
 * its extended-nonce variant ("XForró") powered by *HForró* key derivation.
 * <p>
 * The constructor now accepts either an 8-byte IV (classic Forró) or a 24-byte
 * IV (XForró):
 * <pre>
 *   // Classic 64-bit nonce
 *   new ForroCipher(key32, iv8);
 *
 *   // Extended 192-bit nonce = 16-byte HForró nonce ‖ 8-byte stream nonce
 *   new ForroCipher(key32, iv24);
 * </pre>
 * Length is detected automatically; everything else stays API-compatible.
 * <p>
 * *Built-in self-test* now includes:
 * <ul>
 *   <li>Official 128-byte keystream vectors from <code>test_ref.c</code></li>
 *   <li>The HForró KDF vector from the <em>HForro.NET</em></li>
 * </ul>
 */
public final class ForroCipher {

    /* =========  Constants  ========= */

    private static int DOUBLE_ROUNDS = 7; // number of double rounds

    /** ASCII bytes of "voltadaasabranca" (little-end encoded) */
    private static final byte[] SIGMA = {'v','o','l','t','a','d','a','a','s','a','b','r','a','n','c','a'};

    // ===== HForró sizes =====
    private static final int HF_OUT = 32;
    private static final int HF_NONCE = 16;

    private int[] state = new int[16]; // internal 512-bit state (16×32-bit words)
    
    /* Reset method */
    public void resetState() {
	state = new int[16];
    }
    
    public String getCipherName() {
    	return "Forró";
    }
    
    public String getCipherNameWithRounds() {
    	return "Forró" + DOUBLE_ROUNDS*2;
    }
    
    public int getCipherRounds() {
    	return DOUBLE_ROUNDS*2;
    }
    
    public int getDefaultCipherRounds() {
    	return 7*2;
    }
    
    public void resetRounds() {
    	DOUBLE_ROUNDS = 7;
    }
    
    public void setCipherDoubleRounds(int doubleRounds) {
    	DOUBLE_ROUNDS = doubleRounds;
    }

    /* =========  Construction ========= */

    /**
     * Creates a Forró or XForró cipher depending on <code>iv</code> length:
     * <ul>
     *   <li>8  bytes → classic Forró</li>
     *   <li>24 bytes → XForró (HForró(key, iv[0..15]) derives sub-key; iv[16..23]
     *       becomes the actual stream nonce)</li>
     * </ul>
     * @throws IllegalArgumentException if key ≠ 32 bytes or iv ≠ 8/24 bytes.
     */
    public ForroCipher(byte[] key, byte[] iv) {
        if (key == null || key.length != 32)
            throw new IllegalArgumentException("Key must be 256 bit / 32 bytes");
        if (iv == null || (iv.length != 8 && iv.length != 24))
            throw new IllegalArgumentException("IV must be 64 bit / 8 bytes (Forró) or 192 bit / 24 bytes (XForró)");

        if (iv.length == 8) {
            // Classic Forró
            keySetup(key);
            ivSetup(iv);
        } else {
            // XForró = HForró-derived key ‖ tail-IV
            byte[] derivedKey = new byte[HF_OUT];
            hforroDeriveKey(derivedKey, key, iv);         // iv holds 24 bytes
            keySetup(derivedKey);
            byte[] tail = new byte[8];
            for (int i = 0; i < 8; i++) tail[i] = iv[HF_NONCE + i];
            ivSetup(tail);
        }
    }

    /* =========  Public API (unchanged) ========= */

    public void encrypt(byte[] in, int inOff, byte[] out, int outOff, int len) {
        if (len == 0) return;
        checkBounds(in, inOff, len);
        checkBounds(out, outOff, len);
        process(in, inOff, out, outOff, len);
    }

    public void decrypt(byte[] in, int inOff, byte[] out, int outOff, int len) {
        encrypt(in, inOff, out, outOff, len);
    }

    public void keystream(byte[] out, int outOff, int len) {
        checkBounds(out, outOff, len);
        for (int i = 0; i < len; i++) out[outOff + i] = 0;
        encrypt(out, outOff, out, outOff, len);
    }

    /* =========  Core stream generation ========= */

    private void process(byte[] in, int inOff, byte[] out, int outOff, int len) {
        byte[] block = new byte[64];
        int remaining = len, mPos = inOff, cPos = outOff;
        while (true) {
            core(block);
            state[4] += 1;               // 64-bit counter increment
            if (state[4] == 0) state[5] += 1;
            int bs = remaining <= 64 ? remaining : 64;
            for (int i = 0; i < bs; i++) {
                out[cPos + i] = (byte) (in[mPos + i] ^ block[i]);
            }
            if (remaining <= 64) return;
            remaining -= 64; mPos += 64; cPos += 64;
        }
    }

    private void core(byte[] output) {
        int[] v = new int[16];
        for (int i = 0; i < 16; i++) v[i] = state[i];
        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            Q(v, 0, 4, 8, 12, 3);
            Q(v, 1, 5, 9, 13, 0);
            Q(v, 2, 6, 10, 14, 1);
            Q(v, 3, 7, 11, 15, 2);
            Q(v, 0, 5, 10, 15, 3);
            Q(v, 1, 6, 11, 12, 0);
            Q(v, 2, 7, 8, 13, 1);
            Q(v, 3, 4, 9, 14, 2);
        }
        for (int i = 0; i < 16; i++) intToLE(v[i] + state[i], output, 4 * i);
    }

    /* =========  HForró (32-byte sub-key KDF) ========= */

    private static void hforroDeriveKey(byte[] outKey, byte[] key, byte[] iv24) {
        // iv24 = 24-byte (16-byte HForró nonce ‖ 8-byte stream nonce)
        byte[] nonce = new byte[HF_NONCE];
        for (int i = 0; i < HF_NONCE; i++) nonce[i] = iv24[i];

        int[] v = new int[16];
        v[0]  = le32(key, 0);
        v[1]  = le32(key, 4);
        v[2]  = le32(key, 8);
        v[3]  = le32(key, 12);
        v[4]  = le32(nonce, 0);
        v[5]  = le32(nonce, 4);
        v[6]  = 0x746c6f76; // "volt"
        v[7]  = 0x61616461; // "aada"
        v[8]  = le32(key, 16);
        v[9]  = le32(key, 20);
        v[10] = le32(key, 24);
        v[11] = le32(key, 28);
        v[12] = le32(nonce, 8);
        v[13] = le32(nonce, 12);
        v[14] = 0x72626173; // "sabr"
        v[15] = 0x61636e61; // "anca"

        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            Q(v, 0, 4, 8, 12, 3);
            Q(v, 1, 5, 9, 13, 0);
            Q(v, 2, 6, 10, 14, 1);
            Q(v, 3, 7, 11, 15, 2);
            Q(v, 0, 5, 10, 15, 3);
            Q(v, 1, 6, 11, 12, 0);
            Q(v, 2, 7, 8, 13, 1);
            Q(v, 3, 4, 9, 14, 2);
        }

        // Compose output: (x6,x7,x14,x15,x4,x5,x12,x13)
        intToLE(v[6],  outKey, 0);
        intToLE(v[7],  outKey, 4);
        intToLE(v[14], outKey, 8);
        intToLE(v[15], outKey, 12);
        intToLE(v[4],  outKey, 16);
        intToLE(v[5],  outKey, 20);
        intToLE(v[12], outKey, 24);
        intToLE(v[13], outKey, 28);
    }

    /* =========  Quarter round ========= */

    private static void Q(int[] v, int a, int b, int c, int d, int e) {
        v[d] += v[e];
        v[c] ^= v[d];
        v[b] += v[c];
        v[b] = rotl(v[b], 10);
        v[a] += v[b];
        v[e] ^= v[a];
        v[d] += v[e];
        v[d] = rotl(v[d], 27);
        v[c] += v[d];
        v[b] ^= v[c];
        v[a] += v[b];
        v[a] = rotl(v[a], 8);
    }

	private static int rotl(int x, int n) {
		return (x << n) | (x >>> (32 - n));
	}

    /* =========  Key/IV setup for classic Forró ========= */

    private void keySetup(byte[] key) {
        state[0] = le32(key, 0);
        state[1] = le32(key, 4);
        state[2] = le32(key, 8);
        state[3] = le32(key, 12);
        state[6] = le32(SIGMA, 0);
        state[7] = le32(SIGMA, 4);
        state[8]  = le32(key, 16);
        state[9]  = le32(key, 20);
        state[10] = le32(key, 24);
        state[11] = le32(key, 28);
        state[14] = le32(SIGMA, 8);
        state[15] = le32(SIGMA, 12);
    }

    private void ivSetup(byte[] iv8) {
        state[4] = 0; state[5] = 0;
        state[12] = le32(iv8, 0);
        state[13] = le32(iv8, 4);
    }

    /* =========  Little-endian helpers ========= */

	private static int le32(byte[] b, int off) {
		return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8) | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
	}
	
	private static void intToLE(int v, byte[] b, int off) {
		b[off] = (byte) v;
		b[off + 1] = (byte) (v >>> 8);
		b[off + 2] = (byte) (v >>> 16);
		b[off + 3] = (byte) (v >>> 24);
	}

	private static void checkBounds(byte[] a, int off, int len) {
		if (off < 0 || len < 0 || off + len > a.length)
			throw new ArrayIndexOutOfBoundsException();
	}

    /* =========  Hex helpers (for demo & tests) ========= */

    private static String toHex(byte[] d) {
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte b : d) { sb.append(Character.forDigit((b >>> 4) & 0xF, 16)); sb.append(Character.forDigit(b & 0xF, 16)); }
        return sb.toString();
    }
    private static byte[] hexToBytes(String hex) {
        int len = hex.length(); byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) out[i / 2] = (byte)((fromHex(hex.charAt(i)) << 4)|fromHex(hex.charAt(i+1)));
        return out;
    }
    private static int fromHex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        throw new IllegalArgumentException("Bad hex: " + c);
    }

    /* =========  Comprehensive self-test ========= */

    public static boolean selfTest() {
        boolean ok = true;
        // --- Classic Forró vectors (128-byte keystreams) ---
        ok &= forroVectors();
        // --- HForró KDF vector from HForró.NET ---
        ok &= hforroVector();
        return ok;
    }

    private static boolean forroVectors() {
        byte[] key1 = "minha vida e andar por este pais".getBytes();
        byte[] iv1  = "mostro a".getBytes();
        byte[] out1 = new byte[128];
        new ForroCipher(key1, iv1).keystream(out1, 0, 128);
        byte[] exp1 = hexToBytes("c5a96c62f29352aff26295b58da0595c62108225f14e331116ad3f7b4ea000fe"+
                                 "c0f0368e421149b26b0b4398db7b3bbb99e3f5d7a91bf028996a8c4651707ef1"+
                                 "dcbee0c1271a0cf7e00eb1bc1e6ff86ef23caca986a0037e02922ba5aa6a1d6d"+
                                 "f09f5bd1c540b0d9d1cc8b3ec390660ae68a8849fb57ea3a71d844e720b48470");
        for (int i = 0; i < 128; i++) if (out1[i] != exp1[i]) return false;

        byte[] key2 = "eu vou mostrar pra voces como se".getBytes();
        byte[] iv2  = "danca o ".getBytes();
        byte[] out2 = new byte[128];
        new ForroCipher(key2, iv2).keystream(out2, 0, 128);
        byte[] exp2 = hexToBytes("4b768c5c174bc9c1ce1b8c2b1face8e45a63f92e21d97b81c89d61900882d927"+
                                 "73c5f7e62a1f297cee9bae88bb6c70477b803acae317c0184674eefa434699b8"+
                                 "50b6a45ed97b3479852a76a6696a23769aaac2d735ff73f28b9dfa8b2242b20b"+
                                 "7c4e68c03d16226ee9066933598443daf3bf437bbcbc9f04c7ecefa6a24fad3d");
        for (int i = 0; i < 128; i++) if (out2[i] != exp2[i]) return false;
        return true;
    }

    private static boolean hforroVector() {
        byte[] expected = hexToBytes("9754128339bd105377908eb53d7f238e7b3732cc48383052d35fd94c943db866");
        byte[] key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); // 32-byte
        byte[] nonce = hexToBytes("000000090000004a0000000031415927"); // 16-byte
        byte[] okm = new byte[HF_OUT];
        byte[] iv24 = new byte[24];
        // build 24-byte iv to exercise ctor but only first 16 bytes used in KDF test
        for (int i = 0; i < 16; i++) iv24[i] = nonce[i];
        // last 8 bytes irrelevant here
        new ForroCipher(key, iv24); // just to make sure ctor doesn't throw
        hforroDeriveKey(okm, key, iv24);
        // System.out.println("HForró           : " + toHex(okm));
        // System.out.println("HForró-Expected  : " + toHex(expected));
        for (int i = 0; i < HF_OUT; i++) if (okm[i] != expected[i]) return false;
        return true;
    }

    /* =========  CLI demo ========= */
    
    private static void forroDemo() {
    	// Extra mini-demo: encrypt & decrypt "Hello Forró!"
        byte[] key = new byte[32];
        byte[] iv  = new byte[8];
        for (int i = 0; i < 32; i++) key[i] = (byte) i;
        for (int i = 0; i < 8;  i++) iv[i]  = (byte) i;

        byte[] plaintext  = "Hello Forró!".getBytes();
        byte[] ciphertext = new byte[plaintext.length];
        byte[] recovered  = new byte[plaintext.length];

        new ForroCipher(key, iv).encrypt(plaintext, 0, ciphertext, 0, plaintext.length);
        new ForroCipher(key, iv).decrypt(ciphertext, 0, recovered, 0, recovered.length);

        System.out.println("Forró plaintext  : " + toHex(plaintext));
        System.out.println("Forró ciphertext : " + toHex(ciphertext));
        System.out.println("Forró recovered  : " + new String(recovered));
    }
    
    private static void xForroDemo() {
    	// Quick XForró demo: 24-byte nonce, encrypt & decrypt "Hello XForró!"
        byte[] key = new byte[32];
        byte[] iv  = new byte[24];
        for (int i = 0; i < 32; i++) key[i] = (byte) i;
        for (int i = 0; i < 24; i++) iv[i]  = (byte) (i * 3); // arbitrary
        byte[] msg = "Hello XForró!".getBytes();
        byte[] cipher = new byte[msg.length];
        new ForroCipher(key, iv).encrypt(msg, 0, cipher, 0, msg.length);
        byte[] plain = new byte[msg.length];
        new ForroCipher(key, iv).decrypt(cipher, 0, plain, 0, msg.length);
        System.out.println("XForró plaintext : " + toHex(msg));
        System.out.println("XForró Ciphertext: " + toHex(cipher));
        System.out.println("XForró Recovered : " + new String(plain));
    }

    public static void main(String[] args) {
        System.out.println(selfTest() ? "[Forró] Self-check OKAY" : "[Forró] Self-check FAILED");
        forroDemo();
        xForroDemo();
    }
}
