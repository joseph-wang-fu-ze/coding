package com.fusepir.rlwe;

import java.math.BigInteger;

/**
 * 负循环 NTT（数论变换）上下文：把一个素数下的多项式乘法从 O(N²) 降到 O(N log N)。
 *
 * <p>为什么需要它：实测表明外部乘积的耗时几乎全部在多项式乘法上，
 * 而论文规模下 N=16384、模数 438 位（更多素数、更多层）会把朴素乘法的成本放大到不可用。
 * NTT 是这一领域的标准做法（MPC4J 的正式实现里也有），不是我们自己发明的优化。
 *
 * <h3>负循环怎么做</h3>
 * 目标是在 Z_p[X]/(X^N+1) 上做乘法。设 ψ 是一个 2N 次本原单位根（要求 2N | p−1），ω = ψ²。
 * <pre>
 *   正向： a_i ← a_i · ψ^i ，再做长度 N 的普通 NTT（根为 ω）
 *   乘法： 逐点相乘
 *   逆向： 长度 N 的逆变换，再 a_i ← a_i · ψ^{−i}
 * </pre>
 * 这样得到的正是负循环卷积。
 */
public final class NttContext {
    /** 多项式次数 */
    public final int n;
    /** 素数模数 */
    public final long p;
    /** 2N 次本原单位根 */
    private final long psi;
    /** ψ 的逆 */
    private final long psiInv;
    /** 长度 N 变换用的根 ω = ψ² */
    private final long omega;
    /** 每一级的旋转因子 */
    private final long[] stageRoot;
    private final long[] stageRootInv;
    /** 位反转置换 */
    private final int[] rev;
    /** N 在模 p 下的逆 */
    private final long nInv;
    /** ψ^i 与 ψ^{−i} 的预计算表 */
    private final long[] psiPow;
    private final long[] psiPowInv;

    private NttContext(int n, long p, long psi) {
        this.n = n;
        this.p = p;
        this.psi = psi;
        this.psiInv = modPow(psi, p - 2, p);
        this.omega = mulMod(psi, psi, p);
        this.nInv = modPow(n, p - 2, p);

        psiPow = new long[n];
        psiPowInv = new long[n];
        long acc = 1;
        long accInv = 1;
        for (int i = 0; i < n; i++) {
            psiPow[i] = acc;
            psiPowInv[i] = accInv;
            acc = mulMod(acc, psi, p);
            accInv = mulMod(accInv, psiInv, p);
        }

        rev = new int[n];
        int bits = Integer.numberOfTrailingZeros(n);
        for (int i = 0; i < n; i++) {
            rev[i] = Integer.reverse(i) >>> (32 - bits);
        }

        stageRoot = new long[bits + 1];
        stageRootInv = new long[bits + 1];
        for (int len = 2; len <= n; len <<= 1) {
            long w = modPow(omega, n / len, p);
            stageRoot[Integer.numberOfTrailingZeros(len)] = w;
            stageRootInv[Integer.numberOfTrailingZeros(len)] = modPow(w, p - 2, p);
        }
    }

    /**
     * 为给定的 N 找一个"NTT 友好"的素数：满足 2N | p−1，位宽为 bits，
     * 且不小于 {@code 2^(bits-1) + seedOffset}。
     *
     * <p>这样 ψ 才存在（p−1 能被 2N 整除时，乘法群里有 2N 次本原单位根）。
     * 注意候选值必须**向上**对齐到 ≡1 (mod 2N)：向下对齐会跑到起点之前，
     * 于是可能又搜到上一个素数（实测踩过，表现为 CRT 逆元不存在）。
     */
    public static long findPrime(int bits, int n, long seedOffset) {
        BigInteger twoN = BigInteger.valueOf(2L * n);
        BigInteger start = BigInteger.ONE.shiftLeft(bits - 1).add(BigInteger.valueOf(seedOffset));
        BigInteger rem = start.subtract(BigInteger.ONE).mod(twoN);
        BigInteger cand = start.add(twoN.subtract(rem).mod(twoN));
        for (int i = 0; i < 200000; i++) {
            if (cand.bitLength() == bits && cand.isProbablePrime(40)) {
                return cand.longValue();
            }
            cand = cand.add(twoN);
            if (cand.bitLength() > bits) {
                throw new IllegalStateException(
                    "在 " + bits + " 位范围内找不到更多 NTT 友好素数（已尝试 " + i + " 个候选）");
            }
        }
        throw new IllegalStateException("找不到 NTT 友好的素数: bits=" + bits + ", n=" + n);
    }

    /** 取一个 2N 次本原单位根 */
    public static long findPsi(long p, int n) {
        long twoN = 2L * n;
        long exponent = (p - 1) / twoN;
        for (long g = 2; g < 1000; g++) {
            long psi = modPow(g, exponent, p);
            if (psi == 1) {
                continue;
            }
            // 检查阶恰为 2N：psi^N == -1
            if (modPow(psi, n, p) == p - 1) {
                return psi;
            }
        }
        throw new IllegalStateException("找不到 N 次本原单位根: p=" + p + ", n=" + n);
    }

    /** 按素数构造上下文；若该素数不满足 2N | p−1 则抛异常 */
    public static NttContext create(int n, long p) {
        if (n < 2 || Integer.bitCount(n) != 1) {
            throw new IllegalArgumentException("N 必须是 2 的幂: " + n);
        }
        if ((p - 1) % (2L * n) != 0) {
            throw new IllegalArgumentException("素数不满足 2N | p-1: p=" + p + ", N=" + n);
        }
        return new NttContext(n, p, findPsi(p, n));
    }

    /** 正向变换（负循环版）：系数域 → NTT 域 */
    public long[] forward(long[] a) {
        long[] t = new long[n];
        for (int i = 0; i < n; i++) {
            t[i] = mulMod(a[i], psiPow[i], p);
        }
        ntt(t, false);
        return t;
    }

    /** 逆向变换（负循环版）：NTT 域 → 系数域 */
    public long[] inverse(long[] a) {
        long[] t = a.clone();
        ntt(t, true);
        long[] out = new long[n];
        for (int i = 0; i < n; i++) {
            out[i] = mulMod(t[i], psiPowInv[i], p);
        }
        return out;
    }

    /** 逐点相乘（在 NTT 域里就是多项式乘法） */
    public long[] pointwise(long[] a, long[] b) {
        long[] r = new long[n];
        for (int i = 0; i < n; i++) {
            r[i] = mulMod(a[i], b[i], p);
        }
        return r;
    }

    /** 逐点乘积累加：acc += a ⊙ b */
    public void pointwiseAccumulate(long[] acc, long[] a, long[] b) {
        for (int i = 0; i < n; i++) {
            acc[i] = (acc[i] + mulMod(a[i], b[i], p)) % p;
        }
    }

    private void ntt(long[] a, boolean invert) {
        for (int i = 0; i < n; i++) {
            int j = rev[i];
            if (i < j) {
                long tmp = a[i];
                a[i] = a[j];
                a[j] = tmp;
            }
        }
        for (int len = 2; len <= n; len <<= 1) {
            int k = Integer.numberOfTrailingZeros(len);
            long wlen = invert ? stageRootInv[k] : stageRoot[k];
            int half = len >> 1;
            for (int i = 0; i < n; i += len) {
                long w = 1;
                for (int j = 0; j < half; j++) {
                    long u = a[i + j];
                    long v = mulMod(a[i + j + half], w, p);
                    long s = u + v;
                    a[i + j] = s >= p ? s - p : s;
                    long d = u - v;
                    a[i + j + half] = d < 0 ? d + p : d;
                    w = mulMod(w, wlen, p);
                }
            }
        }
        if (invert) {
            for (int i = 0; i < n; i++) {
                a[i] = mulMod(a[i], nInv, p);
            }
        }
    }

    // ---------- 小工具 ----------

    static long mulMod(long a, long b, long m) {
        return a * b % m; // p < 2^31，乘积不会溢出
    }

    static long modPow(long base, long exp, long m) {
        long r = 1;
        long b = base % m;
        long e = exp;
        while (e > 0) {
            if ((e & 1) == 1) {
                r = r * b % m;
            }
            b = b * b % m;
            e >>= 1;
        }
        return r;
    }
}
