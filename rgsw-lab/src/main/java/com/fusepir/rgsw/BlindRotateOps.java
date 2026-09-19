package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;

import java.util.Random;

/**
 * 盲旋转（BlindRotate）——按 CAPE 论文 §2 的定义实现，并测出论文规模下的耗时。
 *
 * <p><b>论文定义</b>：{@code BlindRotate(ct_L, ct_R) → ct'_R}，给定 LWE 加密
 * {@code ct_L ← LWE.Enc_s(r)} 与累加器 {@code P(X) = Σ p_i X^i} 的 RLWE 加密，
 * 按加密下标 r 同态旋转累加器，使 <b>p_r 落到 ct'_R 的常数系数</b>上。
 *
 * <p><b>怎么算</b>：要的就是 {@code Q(X) = X^{−r}·P(X)}（它的常数项恰好是 p_r），而
 * {@code X^{−r} = X^{−b}·X^{⟨a,s⟩} = X^{−b}·Π_i X^{a_i·s_i}}。于是：
 * <pre>
 *   ACC ← P(X) 的密文
 *   对每个 i：ACC ← CMUX(BK_i, ACC, ACC·X^{a_i})    // s_i=0 不动，s_i=1 乘 X^{a_i}
 *   ACC ← ACC · X^{−b}                              // 公开量，无需密钥
 * </pre>
 * 其中 {@code BK_i = RGSW(s_i)}，而 {@code s_i ∈ {0,1}} 正是
 * {@link Mpc4jRgsw#encryptRgswConstant} 支持的常数选择器，所以自举密钥直接可用。
 *
 * <p>注意 LWE 模数取 {@code q_L = 2N}：这样密文系数 a_i 本身就是旋转指数，
 * 不用再做缩放对齐——这正是 CAPE 把 LWE 模数定成 2N 的原因。
 */
public final class BlindRotateOps {

    private BlindRotateOps() {
    }

    /** 盲旋转：返回旋转后的累加器密文（p_r 在常数系数上）。 */
    public static Ciphertext blindRotate(Mpc4jRgsw m, Mpc4jRgsw.Rgsw[] bk, Ciphertext acc,
                                         long[] a, long b) {
        Ciphertext cur = acc;
        for (int i = 0; i < a.length; i++) {
            Ciphertext rotated = m.multiplyPowerOfX(cur, a[i]);
            cur = m.cmux(bk[i], cur, rotated);
        }
        return m.multiplyPowerOfX(cur, -b);
    }

    /** q_L = 2N 下的 LWE 加密：b = ⟨a,s⟩ + r mod 2N。 */
    public static long[][] lweEncryptIndex(int[] s, long r, int qL, Random rnd) {
        long[] a = new long[s.length];
        long sum = 0;
        for (int i = 0; i < s.length; i++) {
            a[i] = Math.floorMod(rnd.nextLong(), qL);
            sum = (sum + a[i] * s[i]) % qL;
        }
        return new long[][]{a, {Math.floorMod(sum + r, qL)}};
    }

    // ------------------------------------------------------------------
    // 测试 + 论文规模耗时
    // ------------------------------------------------------------------

    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("=== 盲旋转（按论文定义）正确性 + 论文规模耗时 ===");

        // ---------- A) 正确性：小参数，能完整建出自举密钥 ----------
        int n = 2048;
        int d = 64;
        int qL = 2 * n;
        Mpc4jRgsw m = new Mpc4jRgsw(n, 65537L, 0, 1 << 16);
        System.out.println("[A] " + m.describe());
        System.out.printf("    LWE: d=%d, q_L=2N=%d%n", d, qL);

        Random rnd = new Random(20260919L);
        int[] s = new int[d];
        for (int i = 0; i < d; i++) {
            s[i] = rnd.nextInt(2);
        }
        long t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw[] bk = new Mpc4jRgsw.Rgsw[d];
        for (int i = 0; i < d; i++) {
            bk[i] = m.encryptRgswConstant(s[i]);
        }
        long bkMs = ms(t0);
        System.out.printf("    自举密钥 %d 个 RGSW（每个 %d 密文），%.0f ms%n",
            d, bk[0].size(), (double) bkMs);

        long[] p = new long[n];
        for (int i = 0; i < n; i++) {
            p[i] = (i % 1000) + 1;
        }
        Ciphertext acc = m.encrypt(p);

        long r = 1234;
        long[][] lwe = lweEncryptIndex(s, r, qL, rnd);
        t0 = System.nanoTime();
        Ciphertext out = blindRotate(m, bk, acc, lwe[0], lwe[1][0]);
        long brMs = ms(t0);

        long[] got = m.decrypt(out);
        long want = p[(int) (r % n)];
        int match = 0;
        for (int i = 0; i < n; i++) {
            // 理想结果是 X^{−r}·P：系数 i 取 p_{(i+r) mod n}，跨过 X^N 的项带负号（即 t − 值）
            int src = (int) ((i + r) % n);
            long expect = (i + r) < n ? p[src] : (p[src] == 0 ? 0 : m.t - p[src]);
            if (got[i] == expect) {
                match++;
            }
        }
        failed += report("A  盲旋转：p_r 落到常数系数", got[0] == want,
            String.format("d=%d, r=%d, 耗时 %.0f ms；常数系数 got=%d want=p_%d=%d；"
                    + "整条累加器与 X^{−r}P 一致的系数 %d/%d",
                d, r, (double) brMs, got[0], r, want, match, n));

        // ---------- B) 论文规模：单步耗时与体积 ----------
        int N = 16384;
        Mpc4jRgsw big = new Mpc4jRgsw(N, 65537L, 0, 1 << 16);
        System.out.println();
        System.out.println("[B] " + big.describe());
        long ctBytes = (long) big.workingPrimeCount * N * 8;
        System.out.printf("    单个密文体积 = %d 素数 × %d × 8B = %.2f MB%n",
            big.workingPrimeCount, N, ctBytes / 1048576.0);

        long[] msg = new long[N];
        for (int i = 0; i < N; i++) {
            msg[i] = (i % 1000) + 1;
        }
        Ciphertext ctB = big.encrypt(msg);

        t0 = System.nanoTime();
        Mpc4jRgsw.Rgsw one = big.encryptRgswConstant(1);
        long rgswMs = ms(t0);
        System.out.printf("[B1] 构造 1 个 RGSW：%d 个密文，%.0f ms，约 %.1f MB%n",
            one.size(), (double) rgswMs, one.size() * ctBytes / 1048576.0);

        t0 = System.nanoTime();
        Ciphertext prod = big.externalProduct(one, ctB);
        long extMs = ms(t0);
        String extOk = big.decrypt(prod)[0] == msg[0] ? "正确" : "错误";
        System.out.printf("[B2] 单次外部乘积：%.0f ms（结果%s）%n", (double) extMs, extOk);

        t0 = System.nanoTime();
        big.multiplyPowerOfX(ctB, 12345L);
        long rotMs = ms(t0);
        System.out.printf("[B3] 单次公开旋转 X^k：%.0f ms%n", (double) rotMs);

        Ciphertext a2 = big.encrypt(msg);
        t0 = System.nanoTime();
        big.cmux(one, ctB, a2);
        long cmuxMs = ms(t0);
        System.out.printf("[B4] 单次 CMUX：%.0f ms（= 1 次外部乘积 + 2 次加法）%n", (double) cmuxMs);

        System.out.println();
        System.out.printf("    外推：一次盲旋转 = d × (CMUX + 旋转)，按 d 计：%n");
        for (int dd : new int[]{64, 128, 256, 512}) {
            System.out.printf("      d=%4d → 约 %8.1f s，自举密钥约 %8.1f MB%n",
                dd, dd * (cmuxMs + rotMs) / 1000.0, dd * one.size() * ctBytes / 1048576.0);
        }

        System.out.println();
        System.out.println(failed == 0 ? "=== 盲旋转正确性通过 ===" : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
