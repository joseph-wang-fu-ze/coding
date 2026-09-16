package cape.he;

import java.util.Random;

/**
 * Diagnostic: measure the ACTUAL phase error and compare it with the
 * theoretical model used in LWESelfTest.
 *
 * This exists because the parameter sweep disagreed with the naive model
 *     sigma_phase = sigma * sqrt((1 + E[s^2]) * d)
 * so we measure instead of guessing.
 */
public final class NoiseDiag {

    public static void main(String[] args) {
        System.out.println("=== measuring actual phase error ===");
        System.out.printf("%-34s %-12s %-12s %-10s %s%n",
                "params", "sigma_ph(obs)", "sigma_ph(theory)", "ratio", "fails");
        System.out.println("-".repeat(90));

        long[][] configs = {
                {1024, 32, 256, 6},
                {1024, 32, 256, 250000},
                {4096, 32, 256, 400000},
                {8192, 32, 256, 700000},
                {1024, 32, 65536, 30000},
        };

        for (long[] c : configs) {
            int d = (int) c[0];
            long q = 1L << c[1];
            int t = (int) c[2];
            double sigma = c[3];

            LWEParams p = new LWEParams(d, q, t, sigma);
            LWE lwe = new LWE(p, new Random(999L));
            LWESecretKey sk = lwe.keyGen();

            // measure phase error: phase should equal Delta*m exactly (noise aside)
            int samples = 2000;
            double sum = 0, sumSq = 0;
            long maxAbs = 0;
            int fails = 0;

            for (int i = 0; i < samples; i++) {
                long m = 0; // fix m = 0 so phase == error exactly
                LWECiphertext ct = lwe.encrypt(sk, m);
                long ph = lwe.phase(sk, ct);
                long centered = ModMath.center(ph, q);
                sum += centered;
                sumSq += (double) centered * centered;
                maxAbs = Math.max(maxAbs, Math.abs(centered));

                long got = lwe.decode(ph);
                if (got != m) {
                    fails++;
                }
            }
            double mean = sum / samples;
            double obs = Math.sqrt(Math.max(0, sumSq / samples - mean * mean));

            // theory: variance(a.s) = sigma_a^2 * sum(s_i^2); sigma_a = sigma (coefficients uniform in Z_q)
            long sumSqS = 0;
            for (long si : sk.getS()) {
                sumSqS += si * si;
            }
            double theory = sigma * Math.sqrt(sumSqS);

            String label = String.format("d=%d q=2^%d t=%d s=%.0f", d, c[1], t, sigma);
            System.out.printf("%-34s %-12.4g %-12.4g %-10.4f %d/%d%n",
                    label, obs, theory, obs / theory, fails, samples);
            System.out.printf("%-34s (max|e|=%d, sum(s^2)=%d, Delta/2=%d)%n",
                    "", maxAbs, sumSqS, p.errorTolerance());
        }

        System.out.println();
        System.out.println("KEY QUESTION: is sigma_phase really ~ sigma*sqrt(sum s^2)?");
        System.out.println("If obs/theory ~= 1, the model is right and the sweep's");
        System.out.println("failure counts need re-deriving. If not, the sampler or");
        System.out.println("the reduction is doing something unintended.");
    }
}
