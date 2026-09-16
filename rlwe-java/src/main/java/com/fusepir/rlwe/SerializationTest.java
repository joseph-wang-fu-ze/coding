package com.fusepir.rlwe;

import java.math.BigInteger;
import java.util.Random;

/**
 * 序列化 / 通信量统计 的自检（本轮第 4 项）。
 *
 * <p>用法：<code>java -cp out com.fusepir.rlwe.SerializationTest</code>
 *
 * <p>验证：
 * <ol>
 *   <li>序列化 → 反序列化后<b>逐位一致</b>，且解密结果不变；</li>
 *   <li>实际字节数与 {@link Serialization#ciphertextBytes} 的估算一致；</li>
 *   <li>参数不匹配时能明确报错（不是静默出错）。</li>
 * </ol>
 */
public final class SerializationTest {

    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("=== serialization / communication self-test ===");

        RingParams p = RingParams.paperParams(1024, 2);
        System.out.println("[params] " + p.describe());
        System.out.println();

        Random rnd = new Random(20260916L);
        RlweKey key = new RlweKey(p, rnd);

        long[] m = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            m[i] = Math.floorMod(rnd.nextLong(), p.t);
        }
        RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);

        testRoundTrip(p, key, ct, m);
        testSizeMatchesEstimate(p, ct);
        testParamMismatchRejected(p, ct, key);

        System.out.println();
        System.out.println(Serialization.report(p, 16, 512, 64));

        System.out.println();
        if (failed == 0) {
            System.out.println("=== ALL TESTS PASSED ===");
        } else {
            System.out.println("=== " + failed + " TEST(S) FAILED ===");
            System.exit(1);
        }
    }

    private static void testRoundTrip(RingParams p, RlweKey key, RlweCiphertext ct, long[] m) {
        byte[] bytes = Serialization.toBytes(p, ct);
        RlweCiphertext back = Serialization.fromBytes(p, bytes);

        long bitDiff = 0;
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                if (back.c0[k][i] != ct.c0[k][i]) {
                    bitDiff++;
                }
                if (back.c1[k][i] != ct.c1[k][i]) {
                    bitDiff++;
                }
            }
        }
        long[] dec = RlweOps.decrypt(p, key, back);
        long msgDiff = 0;
        for (int i = 0; i < p.n; i++) {
            if (dec[i] != m[i]) {
                msgDiff++;
            }
        }
        report("Test 1  serialize -> deserialize -> decrypt", bitDiff == 0 && msgDiff == 0,
            "coefficient differences = " + bitDiff + ", message differences = " + msgDiff
                + ", bytes = " + bytes.length);
    }

    private static void testSizeMatchesEstimate(RingParams p, RlweCiphertext ct) {
        long actual = Serialization.toBytes(p, ct).length;
        long estimated = Serialization.ciphertextBytes(p);
        // 估算只算"系数"，序列化还有头部（魔数/版本/N/素数表/q位宽）
        long header = 4 + 4 + 4 + 4 + 8L * p.primes.length + 4;
        report("Test 2  byte size matches the analytic estimate",
            actual == estimated + header,
            "actual = " + actual + ", estimate(coefficients) = " + estimated
                + ", header = " + header);
    }

    private static void testParamMismatchRejected(RingParams p, RlweCiphertext ct, RlweKey key) {
        byte[] bytes = Serialization.toBytes(p, ct);
        RingParams other = RingParams.lab();
        boolean rejected = false;
        String msg = "";
        try {
            Serialization.fromBytes(other, bytes);
        } catch (IllegalArgumentException e) {
            rejected = true;
            msg = e.getMessage();
        }
        report("Test 3  parameter mismatch is rejected loudly", rejected,
            rejected ? ("rejected: " + msg) : "NOT rejected (would be a silent bug)");
    }

    private static void report(String name, boolean ok, String detail) {
        if (!ok) {
            failed++;
        }
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
    }
}
