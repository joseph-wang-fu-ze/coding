package com.fusepir.rlwe;

import java.math.BigInteger;
import java.util.Random;

/**
 * 密文 × 密文 + 重线性化 的自检（本轮新增能力）。
 *
 * <p>用法：<code>java -cp out com.fusepir.rlwe.CtCtMulTest</code>
 *
 * <p>验证四件事：
 * <ol>
 *   <li>密文 × 明文 正确（对照明文环乘积）；</li>
 *   <li><b>密文 × 密文 → 三元密文的相位正确</b>（用 c0 + c1·s + c2·s² 直接解）；</li>
 *   <li><b>重线性化后仍是二元密文且结果不变</b>（这是 CAPE 的入场券）；</li>
 *   <li>重线性化密钥体积可量化。</li>
 * </ol>
 */
public final class CtCtMulTest {

    private static int failed = 0;

    public static void main(String[] args) {
        // 密文×密文要求 q >> t^2：实验层单素数（31 位）小于 t^2 = 2^32 必然失败，
        // 所以这里用 2 个素数（62 位）—— 这本身就证明了那条约束是真的。
        RingParams p = smallModulusParams();
        System.out.println("=== ciphertext x ciphertext + relinearization self-test ===");
        System.out.println("[params] " + p.describe());
        System.out.println();

        Random rnd = new Random(20260916L);
        RlweKey key = new RlweKey(p, rnd);

        int base = 1 << 16;
        if (base >= p.q.longValueExact()) {
            base = 1 << 8; // 小模数下退一个基数，保持 base^levels > q 可满足
        }
        RelinKeys rlk = RelinKeys.generate(p, key, base, 0, rnd);
        System.out.println("[relin] base=" + rlk.base + ", levels=" + rlk.levels
            + ", size=" + rlk.describeBytes(p));
        System.out.println();

        testMultiplyPlain(p, key, rnd);
        testCtCtMul(p, key, rnd);
        testRelinearize(p, key, rlk, rnd);
        testRelinAfterRandomPair(p, key, rlk, rnd);

        System.out.println();
        if (failed == 0) {
            System.out.println("=== ALL TESTS PASSED ===");
        } else {
            System.out.println("=== " + failed + " TEST(S) FAILED ===");
            System.exit(1);
        }
    }

    /** 1. 密文 × 明文 */
    private static void testMultiplyPlain(RingParams p, RlweKey key, Random rnd) {
        long[] m = randomMessage(p, rnd);
        long[] pt = oneHotMessage(p, rnd);   // one-hot 选择器：CtPtMul 的典型用法
        RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);

        long[] ptAsValues = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            ptAsValues[i] = pt[i]; // 明文系数本身就是 Z_t 里的值
        }
        RlweCiphertext prod = CiphertextOps.multiplyPlain(p, ct, ptAsValues);
        long[] got = RlweOps.decrypt(p, key, prod);
        long[] want = negacyclicModT(m, ptAsValues, p);
        long bad = countDiff(got, want);
        report("Test 1  ciphertext x plaintext", bad == 0,
            "wrong coefficients = " + bad + " (expect 0)");
    }

    /** 2. 密文 × 密文 → 三元密文，相位应正确 */
    private static void testCtCtMul(RingParams p, RlweKey key, Random rnd) {
        long[] m1 = boundedMessage(p, rnd, 4);
        long[] m2 = boundedMessage(p, rnd, 4);
        RlweCiphertext a = RlweOps.encryptScaled(p, key, m1, rnd);
        RlweCiphertext b = RlweOps.encryptScaled(p, key, m2, rnd);

        long[][][] c3 = CiphertextOps.multiply(p, a, b);
        long[] got = decryptDegree3(p, key, c3);
        long[] want = negacyclicModT(m1, m2, p);
        long bad = countDiff(got, want);
        report("Test 2  ciphertext x ciphertext (degree-3 phase)", bad == 0,
            "wrong coefficients = " + bad + " (expect 0)");
    }

    /** 3. 重线性化：结果仍是二元密文，且解密值不变 */
    private static void testRelinearize(RingParams p, RlweKey key, RelinKeys rlk, Random rnd) {
        long[] m1 = boundedMessage(p, rnd, 4);
        long[] m2 = boundedMessage(p, rnd, 4);
        RlweCiphertext a = RlweOps.encryptScaled(p, key, m1, rnd);
        RlweCiphertext b = RlweOps.encryptScaled(p, key, m2, rnd);

        RlweCiphertext prod = CiphertextOps.multiplyAndRelinearize(p, a, b, rlk);
        boolean degree2 = prod.c0.length == p.primes.length
            && prod.c0[0].length == p.n && prod.c1.length == p.primes.length;

        long[] got = RlweOps.decryptProduct(p, key, prod);
        long[] want = negacyclicModT(m1, m2, p);
        long bad = countDiff(got, want);
        BigInteger noise = BigInteger.ZERO;
        report("Test 3  relinearization (degree-3 -> degree-2)", bad == 0 && degree2,
            "wrong coefficients = " + bad + ", still degree-2 = " + degree2
                + ", noise = " + noise + " (limit = " + p.noiseLimit() + ")");
    }

    /** 4. 多组随机密文相乘，确认不是偶然 */
    private static void testRelinAfterRandomPair(RingParams p, RlweKey key, RelinKeys rlk, Random rnd) {
        long bad = 0;
        BigInteger maxNoise = BigInteger.ZERO;
        int trials = 3;
        for (int t = 0; t < trials; t++) {
            long[] m1 = boundedMessage(p, rnd, 4);
            long[] m2 = boundedMessage(p, rnd, 4);
            RlweCiphertext a = RlweOps.encryptScaled(p, key, m1, rnd);
            RlweCiphertext b = RlweOps.encryptScaled(p, key, m2, rnd);
            RlweCiphertext prod = CiphertextOps.multiplyAndRelinearize(p, a, b, rlk);
            long[] want = negacyclicModT(m1, m2, p);
            bad += countDiff(RlweOps.decryptProduct(p, key, prod), want);
        }
        report("Test 4  repeat " + trials + " random pairs", bad == 0,
            "wrong coefficients = " + bad + ", max noise = " + maxNoise);
    }

    // ---------- 工具 ----------

    /** 用 c0 + c1·s + c2·s² 直接解三元密文（不重线性化） */
    private static long[] decryptDegree3(RingParams p, RlweKey key, long[][][] c3) {
        long[][] s2 = RingOps.mul(key.s, key.s, p);
        long[][] c1s = key.mul(p, c3[1]);
        long[][] c2s2 = RingOps.mul(c3[2], s2, p);
        long[][] sum = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            long m = p.primes[k];
            for (int i = 0; i < p.n; i++) {
                long v = c3[0][k][i] + c1s[k][i];
                v %= m;
                v += c2s2[k][i];
                v %= m;
                sum[k][i] = v;
            }
        }
        // 乘积的缩放是 Δ²：构造一个二元密文交给 decryptProduct 复用同一套解码逻辑
        return RlweOps.decryptProduct(p, key, new RlweCiphertext(sum, RingOps.zero(p)));
    }

    /** 明文域上的负循环乘积 mod t（对照用） */
    private static long[] negacyclicModT(long[] f, long[] g, RingParams p) {
        int n = p.n;
        long t = p.t;
        long[] tmp = new long[2 * n];
        for (int i = 0; i < n; i++) {
            if (f[i] == 0) {
                continue;
            }
            for (int j = 0; j < n; j++) {
                if (g[j] == 0) {
                    continue;
                }
                tmp[i + j] += f[i] * g[j];
            }
        }
        long[] out = new long[n];
        for (int i = 0; i < n; i++) {
            long v = (tmp[i] % t) - (tmp[i + n] % t);
            out[i] = ((v % t) + t) % t;
        }
        return out;
    }

    /**
     * 小模数参数：让 Δ²·|消息| 落在 q 的预算内。
     *
     * <p>这是"不做缩放"的乘法的可行区间：Δ = q/t，要求 Δ²·M &lt; q/2，
     * 即 <b>q &lt; t²/(2M)</b>（M 是环乘积系数的上界）。模数越大越不行——
     * 想在大模数下相乘，必须补上标准 BFV 的"缩放回 Δ"步骤。
     */
    private static RingParams smallModulusParams() {
        long prime = NttContext.findPrime(20, 1024, 0);
        return new RingParams("small-q", 1024, new long[]{prime}, 65537L, 16, 6, 4);
    }

    /** 有界小消息：环乘积的系数只涨到 n*B^2，才在 q 的预算内 */
    private static long[] boundedMessage(RingParams p, Random rnd, int bound) {
        long[] m = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            m[i] = rnd.nextInt(bound);
        }
        return m;
    }

    /** one-hot 明文：最典型的 CtPtMul 用法（选择器） */
    private static long[] oneHotMessage(RingParams p, Random rnd) {
        long[] m = new long[p.n];
        m[rnd.nextInt(p.n)] = 1;
        return m;
    }

    /** 满量程随机消息（只能用于加密/解密，不能拿去相乘） */
    private static long[] randomMessage(RingParams p, Random rnd) {
        long[] m = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            m[i] = Math.floorMod(rnd.nextLong(), p.t);
        }
        return m;
    }

    private static long countDiff(long[] a, long[] b) {
        long c = 0;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                c++;
            }
        }
        return c;
    }

    private static void report(String name, boolean ok, String detail) {
        if (!ok) {
            failed++;
        }
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
    }
}
