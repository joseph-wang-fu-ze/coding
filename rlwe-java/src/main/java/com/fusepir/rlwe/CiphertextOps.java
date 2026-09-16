package com.fusepir.rlwe;

import java.math.BigInteger;

/**
 * 密文之间的运算：加法、密文 × 明文、密文 × 密文、重线性化。
 *
 * <p>密文约定：相位 = c0 + c1·s。于是
 * <pre>
 *   (a0 + a1 s)(b0 + b1 s) = a0b0 + (a0b1 + a1b0) s + (a1b1) s²
 * </pre>
 * 即"密文 × 密文"天然得到一个<b>三元</b>密文 (a0b0, a0b1+a1b0, a1b1)，
 * 必须再重线性化（{@link #relinearize}）才能继续参与后续运算。
 *
 * <h3>⚠️ 两条硬约束（实测踩过，写在这里免得再踩）</h3>
 * <ol>
 *   <li><b>q 必须明显大于 t²</b>：乘积的相位变成 Δ²·(m1⊛m2)，要求 Δ²·|消息| &lt; q/2。
 *       实验层的单素数模数（31 位）**小于** t² = 2³²，所以密文 × 密文必然错；
 *       至少要用 2 个素数（62 位）才成立。</li>
 *   <li><b>消息不能是满量程随机值</b>：环乘积的系数会涨到 n·max²，
 *       所以真正能安全相乘的是<b>小消息</b>——例如 CAPE 的加密 Bloom 得分
 *       （两个 0/1 向量逐位相乘，系数只有 0/1）、以及各种选择器。
 *       拿"Z_t 上的满量程随机多项式"去相乘，在 BFV 里本来就不合法。</li>
 * </ol>
 */
public final class CiphertextOps {

    private CiphertextOps() {
    }

    // ---------------- 加减 ----------------

    public static RlweCiphertext add(RingParams p, RlweCiphertext x, RlweCiphertext y) {
        long[][] c0 = new long[p.primes.length][p.n];
        long[][] c1 = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            long m = p.primes[k];
            for (int i = 0; i < p.n; i++) {
                long a = x.c0[k][i] + y.c0[k][i];
                c0[k][i] = a >= m ? a - m : a;
                long b = x.c1[k][i] + y.c1[k][i];
                c1[k][i] = b >= m ? b - m : b;
            }
        }
        return new RlweCiphertext(c0, c1);
    }

    public static RlweCiphertext sub(RingParams p, RlweCiphertext x, RlweCiphertext y) {
        long[][] c0 = new long[p.primes.length][p.n];
        long[][] c1 = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            long m = p.primes[k];
            for (int i = 0; i < p.n; i++) {
                long a = x.c0[k][i] - y.c0[k][i];
                c0[k][i] = a < 0 ? a + m : a;
                long b = x.c1[k][i] - y.c1[k][i];
                c1[k][i] = b < 0 ? b + m : b;
            }
        }
        return new RlweCiphertext(c0, c1);
    }

    /**
     * 乘一个明文多项式（论文里的 CtPtMul）。
     *
     * <p>明文按"未缩放"的整数值处理，所以结果的缩放因子不变（仍是 Δ），
     * 这与"密文 × 密文"（缩放变成 Δ²）不同。实践中明文应当是<b>小值</b>
     * ——典型用法是 one-hot 选择器（0/1）或 gadget 切段数字。
     */
    public static RlweCiphertext multiplyPlain(RingParams p, RlweCiphertext ct, long[] plain) {
        long[][] pt = RlweOps.toPrimePoly(p, plain);
        return new RlweCiphertext(RingOps.mul(ct.c0, pt, p), RingOps.mul(ct.c1, pt, p));
    }

    // ---------------- 密文 × 密文 ----------------

    /**
     * 密文 × 密文 → <b>三元</b>密文。
     *
     * <p>结果形状：[分量 0/1/2][素数][系数]。调用方随后应当用
     * {@link #relinearize} 降回二元——除非只是想验算。
     */
    public static long[][][] multiply(RingParams p, RlweCiphertext a, RlweCiphertext b) {
        int kp = p.primes.length;
        long[][][] out = new long[3][kp][p.n];
        for (int j = 0; j < kp; j++) {
            NttContext ctx = p.ntt[j];
            if (ctx == null) {
                long[] t1a = RingOps.mulSchoolbook(a.c0[j], b.c1[j], p, j);
                long[] t1b = RingOps.mulSchoolbook(a.c1[j], b.c0[j], p, j);
                long[] t1 = new long[p.n];
                for (int i = 0; i < p.n; i++) {
                    t1[i] = addNaive(t1a[i], t1b[i], p.primes[j]);
                }
                out[0][j] = RingOps.mulSchoolbook(a.c0[j], b.c0[j], p, j);
                out[1][j] = t1;
                out[2][j] = RingOps.mulSchoolbook(a.c1[j], b.c1[j], p, j);
                continue;
            }
            // NTT 域：每个分量只变换一次
            long[] a0 = ctx.forward(a.c0[j]);
            long[] a1 = ctx.forward(a.c1[j]);
            long[] b0 = ctx.forward(b.c0[j]);
            long[] b1 = ctx.forward(b.c1[j]);
            long[] t0 = new long[p.n];
            long[] t1 = new long[p.n];
            long[] t2 = new long[p.n];
            for (int i = 0; i < p.n; i++) {
                t0[i] = ctx.mul(a0[i], b0[i]);
                t1[i] = ctx.addMod(ctx.mul(a0[i], b1[i]), ctx.mul(a1[i], b0[i]));
                t2[i] = ctx.mul(a1[i], b1[i]);
            }
            ctx.inverseInplace(t0);
            ctx.inverseInplace(t1);
            ctx.inverseInplace(t2);
            out[0][j] = t0;
            out[1][j] = t1;
            out[2][j] = t2;
        }
        return out;
    }

    /**
     * 重线性化：三元密文 → 二元密文。
     *
     * <p>把第三分量切段，去乘"s² 的重线性化密钥"并累加到前两个分量上。
     * 切段数字是公开的，所以这一步只是"密文乘公开多项式"，不会引入新的密文度数。
     */
    public static RlweCiphertext relinearize(RingParams p, long[][][] ct3, RelinKeys rlk) {
        BigInteger cap = BigInteger.valueOf(rlk.base).pow(rlk.levels);
        if (cap.compareTo(p.q) <= 0) {
            throw new IllegalArgumentException(
                "重线性化密钥层数不足：base^levels 必须 > q（当前 base=" + rlk.base
                    + ", levels=" + rlk.levels + ", q 有 " + p.qBits + " 位）");
        }
        BigInteger[] v2 = RingOps.crtPoly(p, ct3[2]);
        long[][] digits = Gadget.decompose(p, v2, rlk.base, rlk.levels);

        long[][] r0 = copyPolys(p, ct3[0]);
        long[][] r1 = copyPolys(p, ct3[1]);
        for (int i = 0; i < rlk.levels; i++) {
            long[][] digitPoly = RlweOps.toPrimePoly(p, digits[i]);
            RingOps.addInplace(r0, RingOps.mulSmall(digitPoly, rlk.keys[i].c0, p), p);
            RingOps.addInplace(r1, RingOps.mulSmall(digitPoly, rlk.keys[i].c1, p), p);
        }
        return new RlweCiphertext(r0, r1);
    }

    /** 密文 × 密文 + 重线性化（最常用的一步） */
    public static RlweCiphertext multiplyAndRelinearize(RingParams p, RlweCiphertext a,
                                                        RlweCiphertext b, RelinKeys rlk) {
        return relinearize(p, multiply(p, a, b), rlk);
    }

    private static long[][] copyPolys(RingParams p, long[][] src) {
        long[][] out = new long[p.primes.length][];
        for (int k = 0; k < p.primes.length; k++) {
            out[k] = src[k].clone();
        }
        return out;
    }

    private static long addNaive(long a, long b, long m) {
        long s = a + b;
        return s >= m ? s - m : s;
    }
}
