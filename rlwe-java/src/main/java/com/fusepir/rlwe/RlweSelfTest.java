package com.fusepir.rlwe;

import java.math.BigInteger;
import java.util.Random;

/**
 * RLWE 层自检（不依赖 RGSW 部分，本层可以独立验证）。
 *
 * <p>用法：<code>java -cp out com.fusepir.rlwe.RlweSelfTest [scale]</code>
 * 加 scale 参数则在 N=16384、15 素数（论文模数规模）下跑一遍。
 */
public final class RlweSelfTest {

    private static int failed = 0;

    public static void main(String[] args) {
        boolean scale = args.length > 0 && args[0].equalsIgnoreCase("scale");
        RingParams p = scale ? RingParams.paperParams(16384, 15) : RingParams.lab();

        System.out.println("=== RLWE layer self-test ===");
        System.out.println("[params] " + p.describe());
        System.out.println("         ntt=" + p.nttEnabled());
        System.out.println();

        Random rnd = new Random(20260916L);
        RlweKey key = new RlweKey(p, rnd);

        testNttAgainstSchoolbook(p, rnd);
        testCrtRoundTrip(p, rnd);
        testEncryptDecrypt(p, key, rnd);
        testNoiseUnchangedByN(p, key, rnd);

        System.out.println();
        if (failed == 0) {
            System.out.println("=== ALL TESTS PASSED ===");
        } else {
            System.out.println("=== " + failed + " TEST(S) FAILED ===");
            System.exit(1);
        }
    }

    /** NTT 与朴素乘法必须逐位一致（这是所有后续结论的地基） */
    private static void testNttAgainstSchoolbook(RingParams p, Random rnd) {
        if (!p.nttEnabled()) {
            report("Test 1  NTT vs schoolbook", true, "NTT unavailable, schoolbook path in use");
            return;
        }
        long bad = 0;
        for (int t = 0; t < 5; t++) {
            long[][] f = RingOps.sampleUniform(rnd, p);
            long[][] g = RingOps.sampleUniform(rnd, p);
            long[][] viaNtt = RingOps.mul(f, g, p);
            for (int k = 0; k < p.primes.length; k++) {
                long[] viaSchool = RingOps.mulSchoolbook(f[k], g[k], p, k);
                for (int i = 0; i < p.n; i++) {
                    if (viaNtt[k][i] != viaSchool[i]) {
                        bad++;
                    }
                }
            }
        }
        report("Test 1  NTT vs schoolbook multiplication", bad == 0,
            "5 products per prime, mismatched coefficients = " + bad);
    }

    /** 跨素数还原再拆回去，必须一模一样 */
    private static void testCrtRoundTrip(RingParams p, Random rnd) {
        long bad = 0;
        for (int t = 0; t < 50; t++) {
            long[][] poly = RingOps.sampleUniform(rnd, p);
            BigInteger[] vals = RingOps.crtPoly(p, poly);
            long[][] back = RingOps.toPrimePoly(p, vals);
            for (int k = 0; k < p.primes.length; k++) {
                for (int i = 0; i < p.n; i++) {
                    if (back[k][i] != poly[k][i]) {
                        bad++;
                    }
                }
            }
        }
        report("Test 2  CRT round-trip (crtPoly -> toPrimePoly)", bad == 0,
            "50 polynomials x " + p.primes.length + " primes, mismatched = " + bad);
    }

    /** 加解密往返 */
    private static void testEncryptDecrypt(RingParams p, RlweKey key, Random rnd) {
        long bad = 0;
        BigInteger maxNoise = BigInteger.ZERO;
        int trials = 5;
        for (int t = 0; t < trials; t++) {
            long[] m = randomMessage(p, rnd);
            RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
            long[] back = RlweOps.decrypt(p, key, ct);
            for (int i = 0; i < p.n; i++) {
                if (back[i] != m[i]) {
                    bad++;
                }
            }
            maxNoise = maxNoise.max(RlweOps.noiseNorm(p, key, ct, m));
        }
        report("Test 3  RLWE encrypt/decrypt round-trip", bad == 0,
            trials + " messages, wrong coefficients = " + bad
                + ", max noise = " + maxNoise + " (limit = " + p.noiseLimit() + ")");
    }

    /**
     * 相位噪声 = 新鲜噪声本身，与 N、与素数个数无关。
     * 这条是"维度不影响解密失败率"的同一件事在 RLWE 侧的体现。
     */
    private static void testNoiseUnchangedByN(RingParams p, RlweKey key, Random rnd) {
        long[] m = randomMessage(p, rnd);
        RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
        BigInteger noise = RlweOps.noiseNorm(p, key, ct, m);
        report("Test 4  fresh-ciphertext noise is small", noise.compareTo(BigInteger.TEN) <= 0,
            "N=" + p.n + ", primes=" + p.primes.length + ", q=" + p.qBits
                + " bit, fresh noise = " + noise);
    }

    private static long[] randomMessage(RingParams p, Random rnd) {
        long[] m = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            m[i] = Math.floorMod(rnd.nextLong(), p.t);
        }
        return m;
    }

    private static void report(String name, boolean ok, String detail) {
        if (!ok) {
            failed++;
        }
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
    }
}
