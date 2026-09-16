package com.fusepir.rlwe;

import java.math.BigInteger;

/**
 * 负循环 NTT（数论变换）上下文：把素数下的多项式乘法从 O(N²) 降到 O(N log N)。
 *
 * <h3>为什么需要它</h3>
 * 实测外部乘积的耗时几乎全部在多项式乘法上，而论文规模（N=16384、模数 451 位）
 * 会把朴素乘法的成本放大到不可用。NTT 是这一领域的标准做法，不是我们自己发明的优化。
 *
 * <h3>负循环怎么做</h3>
 * 目标是 Z_p[X]/(X^N+1)。设 ψ 是一个 2N 次本原单位根（要求 2N | p−1），ω = ψ²。
 * <pre>
 *   正向： a_i ← a_i · ψ^i ，再做长度 N 的普通 NTT（根为 ω）
 *   乘法： 逐点相乘
 *   逆向： 长度 N 的逆变换，再 a_i ← a_i · ψ^{−i}
 * </pre>
 *
 * <h3>快在哪（对标 MPC4J 的同类优化）</h3>
 * <ol>
 *   <li><b>旋转因子全部预算</b>：蝴蝶里原来每次都要算 {@code w = w * wlen}，
 *       现在直接查表 —— 每个蝴蝶少一次模乘；</li>
 *   <li><b>Shoup 乘</b>：固定乘数（旋转因子）的模乘用预计算的商做一次修正，
 *       避开硬件除法（{@code %} 是几十个周期的指令）；</li>
 *   <li><b>Barrett 归约</b>：其余模乘也不再取模，改成"乘高位 + 减法修正"；</li>
 *   <li><b>可复用缓冲区</b>：{@code forwardInto / inverseInplace / pointwiseInto}
 *       让热路径不再反复分配。</li>
 * </ol>
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
    /** Barrett 常数：floor(2^64 / p) */
    private final long barrettMu;
    /** 位反转置换 */
    private final int[] rev;
    /** N 在模 p 下的逆 */
    private final long nInv;
    /** ψ^i 与 ψ^{−i} 的预计算表 */
    private final long[] psiPow;
    private final long[] psiPowInv;
    /** 逆变换的合并收尾系数：psi^{-i} · n^{-1} mod p */
    private final long[] invScale;
    /** 各层旋转因子（Shoup 形式：值 + 预计算的商） */
    private final long[][] stageW;
    private final long[][] stageWShoup;
    private final long[][] stageWInv;
    private final long[][] stageWInvShoup;

    private NttContext(int n, long p, long psi) {
        this.n = n;
        this.p = p;
        this.psi = psi;
        this.psiInv = modPow(psi, p - 2, p);
        long omega = mulModNaive(psi, psi, p);
        this.nInv = modPow(n, p - 2, p);
        this.barrettMu = BigInteger.ONE.shiftLeft(64)
            .divide(BigInteger.valueOf(p)).longValueExact();

        psiPow = new long[n];
        psiPowInv = new long[n];
        long acc = 1;
        long accInv = 1;
        for (int i = 0; i < n; i++) {
            psiPow[i] = acc;
            psiPowInv[i] = accInv;
            acc = mulModNaive(acc, psi, p);
            accInv = mulModNaive(accInv, psiInv, p);
        }
        // 逆变换最后一步要乘 psi^{-i} 和 1/n：合并成一张表，省一次模乘
        long[] invScale = new long[n];
        for (int i = 0; i < n; i++) {
            invScale[i] = mulModNaive(psiPowInv[i], nInv, p);
        }
        this.invScale = invScale;

        int bits = Integer.numberOfTrailingZeros(n);
        rev = new int[n];
        for (int i = 0; i < n; i++) {
            rev[i] = Integer.reverse(i) >>> (32 - bits);
        }

        // 预算每层旋转因子：第 k 层（len = 2^k）用 wlen^j（j < len/2），合计 n-1 个
        stageW = new long[bits + 1][];
        stageWShoup = new long[bits + 1][];
        stageWInv = new long[bits + 1][];
        stageWInvShoup = new long[bits + 1][];
        for (int len = 2; len <= n; len <<= 1) {
            int k = Integer.numberOfTrailingZeros(len);
            int half = len >> 1;
            long wlen = modPow(omega, n / len, p);
            long wlenInv = modPow(wlen, p - 2, p);
            stageW[k] = new long[half];
            stageWShoup[k] = new long[half];
            stageWInv[k] = new long[half];
            stageWInvShoup[k] = new long[half];
            long w = 1;
            long wi = 1;
            for (int j = 0; j < half; j++) {
                stageW[k][j] = w;
                stageWShoup[k][j] = shoupConst(w, p);
                stageWInv[k][j] = wi;
                stageWInvShoup[k][j] = shoupConst(wi, p);
                w = mulModNaive(w, wlen, p);
                wi = mulModNaive(wi, wlenInv, p);
            }
        }
    }

    /**
     * 为给定的 N 找一个"NTT 友好"的素数：满足 2N | p−1，位宽为 bits，
     * 且不小于 {@code 2^(bits-1) + seedOffset}。
     *
     * <p>候选值必须**向上**对齐到 ≡1 (mod 2N)：向下对齐会跑到起点之前，
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
            if (modPow(psi, n, p) == p - 1) {
                return psi;
            }
        }
        throw new IllegalStateException("找不到 2N 次本原单位根: p=" + p + ", n=" + n);
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

    // ---------- 对外变换接口 ----------

    /** 正向变换：系数域 → NTT 域 */
    public long[] forward(long[] a) {
        long[] out = new long[n];
        forwardInto(a, out);
        return out;
    }

    /** 正向变换到调用方给的缓冲区（热路径复用，避免反复分配） */
    public void forwardInto(long[] a, long[] out) {
        for (int i = 0; i < n; i++) {
            out[i] = mul(a[i], psiPow[i]);
        }
        ntt(out, stageW, stageWShoup);
    }

    /** 逆向变换：NTT 域 → 系数域 */
    public long[] inverse(long[] a) {
        long[] out = a.clone();
        inverseInplace(out);
        return out;
    }

    /** 逆向变换（原地）：末尾要同时乘 psi^{-i} 与 1/n（合并成一张表） */
    public void inverseInplace(long[] a) {
        ntt(a, stageWInv, stageWInvShoup);
        for (int i = 0; i < n; i++) {
            a[i] = mul(a[i], invScale[i]);
        }
    }

    /** 逐点相乘（在 NTT 域里就是多项式乘法） */
    public long[] pointwise(long[] a, long[] b) {
        long[] r = new long[n];
        pointwiseInto(a, b, r);
        return r;
    }

    /** 逐点相乘到指定缓冲区 */
    public void pointwiseInto(long[] a, long[] b, long[] out) {
        for (int i = 0; i < n; i++) {
            out[i] = mul(a[i], b[i]);
        }
    }

    /** 逐点乘积累加：acc += a ⊙ b */
    public void pointwiseAccumulate(long[] acc, long[] a, long[] b) {
        for (int i = 0; i < n; i++) {
            acc[i] = addMod(acc[i], mul(a[i], b[i]));
        }
    }

    // ---------- 内部 ----------

    private void ntt(long[] a, long[][] wTab, long[][] wShoupTab) {
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
            int half = len >> 1;
            long[] ws = wTab[k];
            long[] wq = wShoupTab[k];
            for (int i = 0; i < n; i += len) {
                for (int j = 0; j < half; j++) {
                    long u = a[i + j];
                    long v = mulModShoup(a[i + j + half], ws[j], wq[j]);
                    long s = u + v;
                    a[i + j] = s >= p ? s - p : s;
                    long d = u - v;
                    a[i + j + half] = d < 0 ? d + p : d;
                }
            }
        }
    }

    /** Barrett 归约：q = floor(x·μ / 2^64)，再最多两次修正（对外公开给密文运算用） */
    public long mul(long a, long b) {
        long x = a * b;                       // < p² < 2^62，不溢出
        long q = Math.multiplyHigh(x, barrettMu);
        long r = x - q * p;
        if (r >= p) {
            r -= p;
        }
        if (r >= p) {
            r -= p;
        }
        return r;
    }

    /** (a + b) mod p */
    public long addMod(long a, long b) {
        long s = a + b;
        return s >= p ? s - p : s;
    }

    /**
     * Shoup 乘：固定乘数 w 预存 wShoup = floor(w·2^64/p)，一次修正即可。
     *
     * <p>注意必须用<b>无符号</b>乘高位：wShoup 常常 ≥ 2^63，存成 long 后"看起来是负数"，
     * 用有符号的 {@code Math.multiplyHigh} 会算错（曾经就是这么翻车的）。
     */
    private long mulModShoup(long a, long w, long wShoup) {
        long q = Math.unsignedMultiplyHigh(a, wShoup);
        long r = a * w - q * p;
        if (r >= p) {
            r -= p;
        }
        if (r >= p) {
            r -= p;
        }
        return r;
    }

    /** shoupConst = floor(w·2^64/p)，可能 ≥ 2^63，因此用 longValue() 保留无符号位模式 */
    private static long shoupConst(long w, long p) {
        return BigInteger.valueOf(w).shiftLeft(64)
            .divide(BigInteger.valueOf(p)).longValue();
    }

    /** 初始化阶段用的朴素模乘（此时 Barrett 常数尚未就绪） */
    private static long mulModNaive(long a, long b, long m) {
        return a * b % m;
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
