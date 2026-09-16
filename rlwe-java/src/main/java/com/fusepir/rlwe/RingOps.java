package com.fusepir.rlwe;

import java.math.BigInteger;
import java.util.Random;

/**
 * 环上的基本运算与采样。
 *
 * <p>多项式的表示：<code>long[素数下标][系数下标]</code>，每个系数始终归约到 [0, 对应素数)。
 * 单个素数时就是 1 行；两个素数时就是 2 行——这就是"RNS 表示"的雏形。
 */
public final class RingOps {

    private RingOps() {
    }

    // ---------- 标量运算 ----------

    public static long addMod(long a, long b, long m) {
        long v = a + b;
        return v >= m ? v - m : v;
    }

    public static long subMod(long a, long b, long m) {
        long v = a - b;
        return v < 0 ? v + m : v;
    }

    /** 模乘；要求 m 与两个操作数都小于 2^31，保证乘积累加不溢出 */
    public static long mulMod(long a, long b, long m) {
        return a * b % m;
    }

    /** 求 a 在模 m 下的逆元（参数初始化时用一次） */
    public static long inverse(long a, long m) {
        return BigInteger.valueOf(a).modInverse(BigInteger.valueOf(m)).longValue();
    }

    // ---------- 多项式运算（逐素数进行） ----------

    public static long[][] zero(RingParams p) {
        return new long[p.primes.length][p.n];
    }

    /** 逐素数的负循环卷积：有 NTT 上下文就走 NTT（O(N log N)），否则朴素 O(N²) */
    public static long[][] mul(long[][] f, long[][] g, RingParams p) {
        long[][] r = new long[p.primes.length][];
        for (int k = 0; k < p.primes.length; k++) {
            r[k] = multiply(f[k], g[k], p, k);
        }
        return r;
    }

    /** 单个素数上的多项式乘法 */
    public static long[] multiply(long[] f, long[] g, RingParams p, int primeIndex) {
        NttContext ctx = p.ntt[primeIndex];
        if (ctx != null) {
            return ctx.inverse(ctx.pointwise(ctx.forward(f), ctx.forward(g)));
        }
        return mulSingle(f, g, p.n, p.primes[primeIndex]);
    }

    /**
     * 快路径：一个系数很小的多项式乘以一个普通多项式（系数 &lt; 2^31）。
     * 内层不取模，靠"累加不会溢出 64 位"这一点省掉全部取模。
     * 前提：小系数 &lt; 2^18 且 n ≤ 16384，此时 n · 小系数 · 2^31 &lt; 2^63。
     */
    public static long[][] mulSmall(long[][] small, long[][] f, RingParams p) {
        long[][] r = new long[p.primes.length][];
        for (int k = 0; k < p.primes.length; k++) {
            if (p.ntt[k] != null) {
                // 有 NTT 就用 NTT（即使小系数多项式也更快）
                NttContext ctx = p.ntt[k];
                r[k] = ctx.inverse(ctx.pointwise(ctx.forward(small[k]), ctx.forward(f[k])));
                continue;
            }
            for (int i = 0; i < p.n; i++) {
                if (small[k][i] >= (1 << 18)) {
                    throw new IllegalArgumentException("mulSmall 要求小系数 < 2^18，实际为 " + small[k][i]);
                }
            }
            r[k] = mulSmallSingle(small[k], f[k], p.n, p.primes[k]);
        }
        return r;
    }

    /** 单素数上的朴素负循环卷积（供 NTT 正确性自检做对照） */
    public static long[] mulSchoolbook(long[] f, long[] g, RingParams p, int primeIndex) {
        return mulSingle(f, g, p.n, p.primes[primeIndex]);
    }

    private static long[] mulSingle(long[] f, long[] g, int n, long m) {
        long[] tmp = new long[2 * n];
        for (int i = 0; i < n; i++) {
            long fi = f[i];
            if (fi == 0) {
                continue;
            }
            for (int j = 0; j < n; j++) {
                long gj = g[j];
                if (gj == 0) {
                    continue;
                }
                tmp[i + j] = (tmp[i + j] + fi * gj) % m;
            }
        }
        long[] r = new long[n];
        for (int k = 0; k < n; k++) {
            long v = tmp[k] - tmp[k + n];
            if (v < 0) {
                v += m;
            }
            r[k] = v;
        }
        return r;
    }

    private static long[] mulSmallSingle(long[] d, long[] f, int n, long m) {
        long[] tmp = new long[2 * n];
        for (int i = 0; i < n; i++) {
            long di = d[i];
            if (di == 0) {
                continue;
            }
            for (int j = 0; j < n; j++) {
                tmp[i + j] += di * f[j]; // 无取模
            }
        }
        long[] r = new long[n];
        for (int k = 0; k < n; k++) {
            long v = (tmp[k] % m) - (tmp[k + n] % m);
            if (v < 0) {
                v += m;
            }
            r[k] = v;
        }
        return r;
    }

    /**
     * 三元多项式（系数只有 0/±1）乘以普通多项式的专用乘法。
     *
     * <p>为什么需要专用版本：三元密钥里的 −1 是存成 <code>q−1</code> 的，
     * 看着是个接近 2^31 的大数，直接走"小系数快路径"会立刻溢出。
     * 这里按符号做加法/减法即可：每个累加位置最多累加 n 个绝对值小于 2^31 的数，总量 &lt; 2^41，不会溢出。
     */
    public static long[][] mulTernary(long[][] ternary, long[][] f, RingParams p) {
        long[][] r = new long[p.primes.length][];
        for (int k = 0; k < p.primes.length; k++) {
            long m = p.primes[k];
            long[] tmp = new long[2 * p.n];
            for (int i = 0; i < p.n; i++) {
                long si = ternary[k][i];
                if (si == 0) {
                    continue;
                }
                boolean negative = si > m / 2; // 表示 -1
                for (int j = 0; j < p.n; j++) {
                    if (negative) {
                        tmp[i + j] -= f[k][j];
                    } else {
                        tmp[i + j] += f[k][j];
                    }
                }
            }
            long[] out = new long[p.n];
            for (int k2 = 0; k2 < p.n; k2++) {
                long v = ((tmp[k2] - tmp[k2 + p.n]) % m + m) % m;
                out[k2] = v;
            }
            r[k] = out;
        }
        return r;
    }

    public static void addInplace(long[][] f, long[][] g, RingParams p) {
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                f[k][i] = addMod(f[k][i], g[k][i], p.primes[k]);
            }
        }
    }

    public static void subInplace(long[][] f, long[][] g, RingParams p) {
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                f[k][i] = subMod(f[k][i], g[k][i], p.primes[k]);
            }
        }
    }

    public static long[][] scalarMul(long[][] f, long v, RingParams p) {
        long[][] r = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            long vv = ((v % p.primes[k]) + p.primes[k]) % p.primes[k];
            for (int i = 0; i < p.n; i++) {
                r[k][i] = mulMod(f[k][i], vv, p.primes[k]);
            }
        }
        return r;
    }

    /** 大整数标量乘法（gadget 倍数可能超过 64 位）：先按每个素数归约再乘 */
    public static long[][] scalarMulBig(long[][] f, BigInteger v, RingParams p) {
        long[][] r = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            long vk = v.mod(BigInteger.valueOf(p.primes[k])).longValueExact();
            for (int i = 0; i < p.n; i++) {
                r[k][i] = mulMod(f[k][i], vk, p.primes[k]);
            }
        }
        return r;
    }

    /** 逐素数加一个标量多项式 */
    public static void addScalarInplace(long[][] f, long v, RingParams p) {
        for (int k = 0; k < p.primes.length; k++) {
            long vv = ((v % p.primes[k]) + p.primes[k]) % p.primes[k];
            f[k][0] = addMod(f[k][0], vv, p.primes[k]);
        }
    }

    // ---------- 跨素数还原（CRT） ----------

    /**
     * 把一个系数从"各素数下的余数"还原回 [0, q) 上的整数。
     *
     * <p>这就是 mpc4j 的 C++ 实现在切段前必须做的事（那边叫 CRTDecPoly）。
     * 素数较多时 q 远超 64 位，所以返回大整数——每一步的逆元都在参数构造时预先算好了。
     */
    public static BigInteger crt(RingParams p, long[] residues) {
        if (p.primes.length == 1) {
            return BigInteger.valueOf(residues[0]);
        }
        if (p.primes.length == 2) {
            long p0 = p.primes[0];
            long p1 = p.primes[1];
            long diff = subMod(residues[1], residues[0] % p1, p1);
            long t = mulMod(diff, p.crtInv, p1);
            return BigInteger.valueOf(residues[0])
                .add(BigInteger.valueOf(p0).multiply(BigInteger.valueOf(t)));
        }
        // 多个素数：增量式 CRT（每一步的逆元预计算）
        BigInteger x = BigInteger.valueOf(residues[0]);
        BigInteger m = BigInteger.valueOf(p.primes[0]);
        for (int k = 1; k < p.primes.length; k++) {
            BigInteger mk = BigInteger.valueOf(p.primes[k]);
            BigInteger diff = BigInteger.valueOf(residues[k]).subtract(x).mod(mk);
            BigInteger t = diff.multiply(p.crtStepInv[k]).mod(mk);
            x = x.add(m.multiply(t));
            m = m.multiply(mk);
        }
        return x;
    }

    /** 逐系数还原：返回 [0, q) 上的整数数组（大整数） */
    public static BigInteger[] crtPoly(RingParams p, long[][] poly) {
        BigInteger[] out = new BigInteger[p.n];
        long[] residues = new long[p.primes.length];
        for (int i = 0; i < p.n; i++) {
            for (int k = 0; k < p.primes.length; k++) {
                residues[k] = poly[k][i];
            }
            out[i] = crt(p, residues);
        }
        return out;
    }

    /** 把 [0, q) 上的整数变成中心的 (−q/2, q/2] 表示 */
    public static BigInteger center(RingParams p, BigInteger x) {
        return x.compareTo(p.q.shiftRight(1)) > 0 ? x.subtract(p.q) : x;
    }

    /** 逐系数中心化 */
    public static BigInteger[] centerPoly(RingParams p, BigInteger[] values) {
        BigInteger[] out = new BigInteger[p.n];
        for (int i = 0; i < p.n; i++) {
            out[i] = center(p, values[i]);
        }
        return out;
    }

    /** 还原并中心化后的无穷范数（用于观察噪声） */
    public static BigInteger centeredNorm(RingParams p, long[][] poly) {
        BigInteger[] values = crtPoly(p, poly);
        BigInteger max = BigInteger.ZERO;
        for (BigInteger v : values) {
            BigInteger c = center(p, v).abs();
            if (c.compareTo(max) > 0) {
                max = c;
            }
        }
        return max;
    }

    /**
     * 把 [0, q) 上的整数值变成"各素数下的余数"表示。
     */
    public static long[][] toPrimePoly(RingParams p, BigInteger[] values) {
        long[][] out = new long[p.primes.length][p.n];
        BigInteger[] mods = new BigInteger[p.primes.length];
        for (int k = 0; k < p.primes.length; k++) {
            mods[k] = BigInteger.valueOf(p.primes[k]);
        }
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                out[k][i] = values[i].mod(mods[k]).longValueExact();
            }
        }
        return out;
    }

    // ---------- 采样 ----------

    public static long[][] sampleUniform(Random rnd, RingParams p) {
        long[][] f = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                f[k][i] = Math.floorMod(rnd.nextLong(), p.primes[k]);
            }
        }
        return f;
    }

    /** 三元分布密钥：0 的概率 1/2，±1 各 1/4（在模 q 的整数域里就是 0/1/q-1） */
    public static long[][] sampleTernary(Random rnd, RingParams p) {
        long[][] f = new long[p.primes.length][p.n];
        for (int i = 0; i < p.n; i++) {
            int r = rnd.nextInt(4);
            long v = r == 0 ? 1 : (r == 1 ? -1 : 0);
            for (int k = 0; k < p.primes.length; k++) {
                f[k][i] = v >= 0 ? v : p.primes[k] - 1;
            }
        }
        return f;
    }

    public static long[][] sampleNoise(Random rnd, RingParams p) {
        long[][] f = new long[p.primes.length][p.n];
        for (int i = 0; i < p.n; i++) {
            int s = 0;
            for (int b = 0; b < p.noiseBits; b++) {
                s += rnd.nextInt(2);
            }
            long v = s - p.noiseBits / 2;
            for (int k = 0; k < p.primes.length; k++) {
                f[k][i] = v >= 0 ? v : v + p.primes[k];
            }
        }
        return f;
    }
}
