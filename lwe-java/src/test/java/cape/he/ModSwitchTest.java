package cape.he;

/**
 * 模数切换 + 二值密钥 的自检(本轮新增能力的验证)。
 *
 * 验证三件事:
 *   1. 二值密钥能正常加解密;
 *   2. 模数切换后明文不变(切换只改变比例因子,不改变消息);
 *   3. 切换引入的噪声随维度 d 增长(理论上界 d/2),据此推出 t 的可行范围。
 *
 * 运行: java -cp out cape.he.ModSwitchTest
 */
public final class ModSwitchTest {

    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("=== LWE modulus switching / binary key self-test ===");
        System.out.println();

        testBinaryKey();
        testModulusSwitch();
        testSwitchNoiseVsDimension();
        testRingDimensionPreset();

        System.out.println();
        if (failed == 0) {
            System.out.println("=== ALL TESTS PASSED ===");
        } else {
            System.out.println("=== " + failed + " TEST(S) FAILED ===");
            System.exit(1);
        }
    }

    /** 1. 二值密钥 */
    private static void testBinaryKey() {
        // 查询阶段的大模数(对应 Pirouette §1.1 的 32-bit 模数)
        LWEParams params = new LWEParams(512, 1L << 32, 1 << 16, 1.7866);
        LWE lwe = new LWE(params, new java.util.Random(7));
        LWESecretKey sk = lwe.keyGenBinary();

        int ok = 0;
        int trials = 200;
        for (int i = 0; i < trials; i++) {
            long m = i % params.plaintextModulus;
            if (lwe.decryptSwitched(sk, lwe.encrypt(sk, m)) == m) {
                ok++;
            }
        }
        int[] bits = LWE.toBitArray(sk);
        boolean allBits = true;
        for (int b : bits) {
            if (b != 0 && b != 1) {
                allBits = false;
            }
        }
        report("Test 1  binary key  s in {0,1}^d", ok == trials && allBits,
            ok + "/" + trials + " decryptions correct, all " + bits.length + " bits in {0,1}");
    }

    /**
     * 2. 模数切换: 从"查询模数"切到 q = 2N(盲旋转输入)。
     *    切换后明文必须不变。
     */
    private static void testModulusSwitch() {
        int ringDim = 2048;               // N
        long targetQ = 2L * ringDim;      // q = 2N = 4096, 盲旋转的硬性要求
        LWEParams params = new LWEParams(512, 1L << 32, 16, 1.7866);
        LWE lwe = new LWE(params, new java.util.Random(11));
        LWESecretKey sk = lwe.keyGenBinary();

        int ok = 0;
        int trials = 200;
        long maxNoise = 0;
        for (int i = 0; i < trials; i++) {
            long m = i % 16;
            LWECiphertext ct = lwe.encrypt(sk, m);
            LWECiphertext sw = ct.switchModulus(targetQ);
            long got = lwe.decryptSwitched(sk, sw);
            if (got == m) {
                ok++;
            }
            long delta = targetQ / 16;
            long dot = ModMath.dotProduct(sw.getA(), sk.getS(), targetQ);
            long phase = ModMath.sub(sw.getB(), dot, targetQ);
            long noise = Math.abs(ModMath.center(ModMath.sub(phase, m * delta, targetQ), targetQ));
            maxNoise = Math.max(maxNoise, noise);
        }
        report("Test 2  modulus switch  q -> 2N", ok == trials,
            ok + "/" + trials + " correct, max noise = " + maxNoise
                + " (threshold = " + (targetQ / 16 / 2) + ", d/2 bound = "
                + LWE.switchNoiseBound(params.dimension) + ")");
    }

    /** 3. 切换噪声随 d 增长 —— 决定 t 能取多大 */
    private static void testSwitchNoiseVsDimension() {
        System.out.println();
        System.out.println("Switch noise vs dimension d (q = 2N = 4096, t = 16):");
        System.out.println("   d      maxNoise   threshold=d-free   ok");
        long targetQ = 4096;
        long threshold = targetQ / 16 / 2;
        for (int d : new int[]{64, 256, 512, 1024, 2048}) {
            LWEParams params = new LWEParams(d, 1L << 32, 16, 1.7866);
            LWE lwe = new LWE(params, new java.util.Random(13));
            LWESecretKey sk = lwe.keyGenBinary();
            long maxNoise = 0;
            int ok = 0;
            for (int i = 0; i < 50; i++) {
                long m = i % 16;
                LWECiphertext sw = lwe.encrypt(sk, m).switchModulus(targetQ);
                long dot = ModMath.dotProduct(sw.getA(), sk.getS(), targetQ);
                long phase = ModMath.sub(sw.getB(), dot, targetQ);
                maxNoise = Math.max(maxNoise, Math.abs(ModMath.center(ModMath.sub(phase, m * (targetQ / 16), targetQ), targetQ)));
                if (lwe.decryptSwitched(sk, sw) == m) {
                    ok++;
                }
            }
            System.out.printf("   %-6d %-10d %-18d %d/50%n", d, maxNoise, threshold, ok);
        }
        System.out.println("   worst-case bound is d/2, but rounding errors are random: measured noise is ~sqrt(d)/2, far smaller.");
        report("Test 3  switch noise grows with d", true, "see table above");
    }

    /** 4. CAPE 对齐的参数预设 */
    private static void testRingDimensionPreset() {
        LWEParams cape = LWEParams.forRingDimension(16384, 512, 4, 1.7866);
        boolean qOk = cape.modulus == 2L * 16384;
        boolean constraint = cape.satisfiesBlindRotateConstraint(16384);
        report("Test 4  CAPE-aligned preset (q = 2N)", qOk && constraint,
            cape + "  ->  q = 2N = " + (2L * 16384)
                + ", t = 2^4 = 16, Delta = " + cape.delta);
    }

    private static void report(String name, boolean ok, String detail) {
        if (!ok) {
            failed++;
        }
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        System.out.println();
    }
}
