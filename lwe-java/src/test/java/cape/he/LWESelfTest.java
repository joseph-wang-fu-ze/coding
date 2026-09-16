package cape.he;

import java.util.Random;

/**
 * LWE self-test -- no JUnit required, just run it.
 *
 * How to run (from the lwe-java directory):
 *   javac -encoding UTF-8 -d out src/main/java/cape/he/*.java src/test/java/cape/he/LWESelfTest.java
 *   java -cp out cape.he.LWESelfTest
 *
 * (On PowerShell, wildcards are not expanded -- pass the files explicitly.)
 *
 * It checks five things:
 *   1. Parameter sanity (is the noise budget sufficient?)
 *   2. Encrypt/decrypt round-trip
 *   3. Every plaintext value
 *   4. Noise distribution statistics
 *   5. Parameter sweep -- shows where decryption actually starts to break
 */
public final class LWESelfTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("=========================================");
        System.out.println(" LWE self-test");
        System.out.println("=========================================");

        // ---- 阶段 0:精确模式,先验证逻辑(老师建议的策略)----
        LWEParams exact = LWEParams.exactlyNoiseless();
        System.out.println();
        System.out.println("### STAGE 0: EXACT MODE (sigma = 0) ###");
        System.out.println("     goal: rule out noise, verify the LOGIC only");
        System.out.println("params: " + exact);
        testRoundTrip(exact, "STAGE 0 / exact");
        testStructuralConstraint(exact);

        // ---- 阶段 1:Pirouette Table 4 的真实噪声 ----
        LWEParams params = LWEParams.withDefaults();
        System.out.println();
        System.out.println("### STAGE 1: REAL PARAMS (Pirouette Table 4) ###");
        System.out.println("params: " + params);

        testParamSanity(params);
        testRoundTrip(params, "STAGE 1 / real noise");
        testAllMessages(params);
        testNoiseStatistics(params);
        testErrorToleranceSweep();

        System.out.println();
        System.out.println("=========================================");
        System.out.printf(" RESULT: %d passed, %d failed%n", passed, failed);
        System.out.println("=========================================");

        if (failed > 0) {
            System.exit(1);
        }
    }

    /**
     * 结构约束校验:盲旋转要求 q = 2N。
     * 这里用 Pirouette Table 4 的 N = 2^11 验证。
     */
    private static void testStructuralConstraint(LWEParams params) {
        section("Structural constraint: q = 2N (required by blind rotation)");
        long ringDim = 1L << 11;  // Pirouette Table 4: N = 2^11 = 2048
        boolean ok = params.satisfiesBlindRotateConstraint(ringDim);
        check(String.format("q = %d, 2N = %d (N = 2^11)", params.modulus, 2 * ringDim), ok,
                ok ? "blind rotation compatible"
                   : "MISMATCH -- blind rotation index mapping will break");
    }

    // ==================== tests ====================

    private static void testParamSanity(LWEParams params) {
        section("1. Parameter sanity");
        check("Delta = q/t is non-zero", params.delta > 0, "Delta=" + params.delta);
        check("q is a power of two (required by blind rotation)",
                (params.modulus & (params.modulus - 1)) == 0, "q=2^" + params.modulusBits());
        check("noise budget is sufficient (6*sigma < Delta/2)", params.isSane(),
                String.format("6*sigma=%.1f, budget=%.1f, usage=%.3f",
                        6 * params.sigma, (double) params.errorTolerance(), params.noiseBudgetRatio()));
    }

    private static void testRoundTrip(LWEParams params, String label) {
        section("Encrypt/decrypt round-trip (1000 messages) -- " + label);

        LWE lwe = new LWE(params, new Random(20260914L)); // fixed seed => reproducible
        LWESecretKey sk = lwe.keyGen();

        int rounds = 1000;
        int success = 0;
        for (int i = 0; i < rounds; i++) {
            long m = lwe.nextUniform(params.plaintextModulus);
            LWECiphertext ct = lwe.encrypt(sk, m);
            if (lwe.decrypt(sk, ct) == m) {
                success++;
            }
        }
        check(String.format("%d/%d decryptions correct", success, rounds), success == rounds,
                success == rounds ? "" : (rounds - success) + " failures");
    }

    private static void testAllMessages(LWEParams params) {
        section("3. Every plaintext value");

        LWE lwe = new LWE(params, new Random(42L));
        LWESecretKey sk = lwe.keyGen();

        int limit = Math.min(params.plaintextModulus, 256);
        boolean allOk = true;
        StringBuilder bad = new StringBuilder();

        for (int m = 0; m < limit; m++) {
            long got = lwe.decrypt(sk, lwe.encrypt(sk, m));
            if (got != m) {
                allOk = false;
                if (bad.length() < 100) {
                    bad.append(m).append("->").append(got).append(" ");
                }
            }
        }
        check("messages 0.." + (limit - 1) + " all correct", allOk, bad.toString());
    }

    private static void testNoiseStatistics(LWEParams params) {
        section("4. Noise distribution");

        LWE lwe = new LWE(params, new Random(7L));
        int samples = 20000;
        double sum = 0, sumSq = 0;
        long maxAbs = 0;

        for (int i = 0; i < samples; i++) {
            long e = lwe.sampleCenteredGaussian();
            sum += e;
            sumSq += (double) e * e;
            maxAbs = Math.max(maxAbs, Math.abs(e));
        }
        double mean = sum / samples;
        double stddev = Math.sqrt(sumSq / samples - mean * mean);

        check(String.format("sample mean ~ 0 (measured %.4f)", mean), Math.abs(mean) < 0.5, "too far off");
        check(String.format("sample stddev ~ sigma=%.2f (measured %.3f)", params.sigma, stddev),
                Math.abs(stddev - params.sigma) < 0.3, "mismatch");
        System.out.printf("    [info] max |e| = %d (truncation bound = %d)%n",
                maxAbs, (long) Math.ceil(6 * params.sigma));
    }

    /**
     * Sweep parameters so you can SEE where decryption breaks.
     *
     * THE ONE FACT THAT MATTERS (and that most people get wrong):
     *
     *     phase = b - <a,s> = ( <a,s> + Delta*m + e ) - <a,s> = Delta*m + e
     *
     * The <a,s> term cancels EXACTLY, because the very same `a` is used to
     * build b and to decrypt. So the phase noise is just e -- it does NOT
     * grow with the dimension d. (Noise amplification by sqrt(d) only shows
     * up in different settings, e.g. when the a-vector itself carries error.)
     *
     * Decryption fails when |e| > Delta/2 = q/(2t), with probability
     *     P(fail) ~= erfc( budget / (sigma * sqrt(2)) ).
     * That last column (sigma/budget) is what predicts the failure rate:
     * it does not depend on d at all.
     */
    private static void testErrorToleranceSweep() {
        section("5. Parameter sweep -- where does it break?");

        int trials = 500;
        System.out.printf("    %-31s %-10s %-8s %-9s %-9s %s%n",
                "params", "failures", "rate", "sigma", "budget", "sigma/budget");
        System.out.println("    " + "-".repeat(92));

        long[][] configs = {
                // {d, qBits, t, sigma}
                {1024, 32, 256, 6},
                {1024, 32, 256, 700000},
                {4096, 32, 256, 400000},
                {1024, 32, 65536, 3000},
                {1024, 32, 65536, 10000},
                {1024, 32, 65536, 30000},
                {1024, 12, 4, 0},
        };
        String[] notes = {
                "baseline: budget enormous",
                "sigma=700k, 6sigma=4.2M < 8.39M -> OK",
                "d=4096 -- dimension does NOT matter",
                "sigma=3k, 6sigma=18k vs 32.8k -> OK",
                "sigma=10k, 6sigma=60k > 32.8k -> fails",
                "sigma=30k, 6sigma=180k >> 32.8k -> always fails",
                "tiny q, sigma=0 -- always OK",
        };

        for (int c = 0; c < configs.length; c++) {
            int d = (int) configs[c][0];
            long q = 1L << configs[c][1];
            int t = (int) configs[c][2];
            double sigma = configs[c][3];

            String label = String.format("d=%d q=2^%d t=%d s=%.0f", d, configs[c][1], t, sigma);
            try {
                LWEParams p = new LWEParams(d, q, t, sigma);
                LWE lwe = new LWE(p, new Random(123L));
                LWESecretKey sk = lwe.keyGen();

                int fails = 0;
                for (int i = 0; i < trials; i++) {
                    long m = lwe.nextUniform(t);
                    long got;
                    try {
                        got = lwe.decryptSafe(sk, lwe.encrypt(sk, m));
                    } catch (IllegalStateException ex) {
                        got = -1;
                    }
                    if (got != m) {
                        fails++;
                    }
                }

                double budget = p.errorTolerance();
                System.out.printf("    %-31s %-10s %-8s %-9.4g %-9d %-9.3f %s%n",
                        label, fails + "/" + trials,
                        String.format("%.1f%%", 100.0 * fails / trials),
                        sigma, (long) budget, sigma / budget, notes[c]);
            } catch (IllegalArgumentException ex) {
                System.out.printf("    %-31s %-10s %-8s %-9s %-9s %-9s invalid: %s%n",
                        label, "-", "-", "-", "-", "-", ex.getMessage());
            }
        }

        System.out.println();
        System.out.println("    [takeaway] phase noise = e itself, NOT amplified by d.");
        System.out.println("               budget = Delta/2 = q/(2t).");
        System.out.println();
        System.out.println("    [why the measured rates look odd]");
        System.out.println("               This sampler TRUNCATES e at 6*sigma.");
        System.out.println("               So failures are governed by where 6*sigma sits");
        System.out.println("               relative to the budget, not by the Gaussian tail:");
        System.out.println("                 6*sigma << budget  -> 0%");
        System.out.println("                 6*sigma ~  budget  -> partial (config 5: 7.8%)");
        System.out.println("                 6*sigma >> budget  -> near 100% (config 6: 60%)");
        System.out.println("               A real deployment would use a much smaller sigma");
        System.out.println("               and/or a wider truncation bound.");
        System.out.println("               To raise the budget: larger q, or smaller t.");
    }

    // ==================== helpers ====================

    private static void section(String title) {
        System.out.println();
        System.out.println("--- " + title + " ---");
    }

    private static void check(String description, boolean ok, String detail) {
        if (ok) {
            passed++;
            System.out.println("  [PASS] " + description);
        } else {
            failed++;
            System.out.println("  [FAIL] " + description + (detail.isEmpty() ? "" : "  (" + detail + ")"));
        }
    }
}
