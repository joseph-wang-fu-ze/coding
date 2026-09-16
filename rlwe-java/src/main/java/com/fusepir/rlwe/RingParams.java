package com.fusepir.rlwe;

import java.math.BigInteger;

/**
 * 环参数与 gadget 参数。
 *
 * <h3>参数来源（哪些来自论文、哪些是我们自选）</h3>
 * <table border="1">
 *   <tr><th>参数</th><th>来源</th><th>说明</th></tr>
 *   <tr><td>t = 65537</td><td><b>论文</b></td><td>CAPE §5.1 明文模数</td></tr>
 *   <tr><td>N</td><td><b>论文 16384</b></td><td>调试时可用小值</td></tr>
 *   <tr><td>素数个数 / q</td><td>论文用 SEAL 默认配置</td><td>实测 N=16384 时为 <b>9 个素数、共 438 位</b>；
 *       本实验的素数每个 ≤31 位，因此用 15 个素数可以到约 465 位，量级与论文一致</td></tr>
 *   <tr><td>gadget 基数 B、层数 l</td><td><b>论文未给</b></td><td>MPC4J 的 C++ 实现取 B = 2^16、l = 7（对应 124 位模数）；
 *       本实验按 B^l &gt; q 自动取</td></tr>
 *   <tr><td>噪声分布</td><td><b>论文未给</b></td><td>本实验自选</td></tr>
 * </table>
 *
 * <p><b>关于 q 的表示</b>：当素数较多时 q 远超 64 位，因此 q、Δ、gadget 倍数、以及"跨素数还原后的整数值"
 * 一律用 {@link BigInteger}。每个素数下的多项式运算仍然用 long（素数小于 2^31，乘积不溢出），
 * 所以热点路径不受影响。
 */
/**
 * @deprecated <b>不要在新代码里使用本类</b>：本模块已降级为交叉校验工具，
 *     新实现请改用 MPC4J 的 BFV（见 coding/rgsw-lab/Mpc4jRgsw.java）。
 *     保留原因：① 与 MPC4J 互为独立校验；② 只有它能跑 N=16384 / 451 位模数。
 */
public final class RingParams {
    /** 参数集名称（写进日志，便于对照） */
    public final String name;
    /** 多项式次数 N */
    public final int n;
    /** 系数模数的各个素数，每个都小于 2^31 */
    public final long[] primes;
    /** 系数模数 q = 各素数之积 */
    public final BigInteger q;
    /** q 的位宽 */
    public final int qBits;
    /** 明文模数 t */
    public final long t;
    /** 缩放因子 Δ = floor(q / t) */
    public final BigInteger delta;
    /** gadget 基数 B（按 B 进制把密文系数切成若干段） */
    public final int base;
    /** gadget 层数 l（必须满足 B^l > q） */
    public final int levels;
    /** gadget 向量 g_i = B^i mod q */
    public final BigInteger[] gadget;
    /** 噪声分布参数：noiseBits 个随机比特求和再减一半，标准差 ≈ sqrt(noiseBits)/2 */
    public final int noiseBits;
    /** 每个素数对应的 NTT 上下文；建不起来的位置为 null（回退朴素乘法） */
    public final NttContext[] ntt;
    /** 两个素数时跨素数还原的预计算逆元 p0^{-1} mod p1；否则为 0 */
    public final long crtInv;
    /** 多素数增量式 CRT 每一步的逆元：crtStepInv[k] = (p0·…·p_{k-1})^{-1} mod p_k（k≥1） */
    public final BigInteger[] crtStepInv;

    public RingParams(String name, int n, long[] primes, long t, int base, int levels, int noiseBits) {
        this.name = name;
        this.n = n;
        this.primes = primes.clone();
        this.t = t;
        this.base = base;
        this.levels = levels;
        this.noiseBits = noiseBits;

        if (primes.length < 1) {
            throw new IllegalArgumentException("至少需要一个素数");
        }
        BigInteger product = BigInteger.ONE;
        for (int i = 0; i < primes.length; i++) {
            long p = primes[i];
            if (p <= 1 || p >= (1L << 31)) {
                throw new IllegalArgumentException("每个素数必须小于 2^31：" + p);
            }
            for (int j = 0; j < i; j++) {
                if (primes[j] == p) {
                    throw new IllegalArgumentException("素数重复：" + p + "（会让 CRT 的逆元不存在）");
                }
            }
            product = product.multiply(BigInteger.valueOf(p));
        }
        this.q = product;
        this.qBits = q.bitLength();
        this.delta = q.divide(BigInteger.valueOf(t));
        if (delta.signum() == 0) {
            throw new IllegalArgumentException("q / t == 0，噪声余量不足：请增大模数或减小 t");
        }

        // 切段必须能覆盖整个 q，否则高位丢失、外部乘积会静默算错
        BigInteger cap = BigInteger.ONE;
        for (int i = 0; i < levels; i++) {
            cap = cap.multiply(BigInteger.valueOf(base));
        }
        if (cap.compareTo(q) <= 0) {
            throw new IllegalArgumentException(
                "gadget 覆盖不足：base^levels = " + cap + " 必须大于 q = " + q);
        }

        this.gadget = new BigInteger[levels];
        BigInteger v = BigInteger.ONE;
        BigInteger bq = BigInteger.valueOf(base);
        for (int i = 0; i < levels; i++) {
            gadget[i] = v.mod(q);
            v = v.multiply(bq);
        }

        // 每个素数尽量建立 NTT 上下文（要求 2N | p-1）。建立不了就回退到朴素乘法。
        this.ntt = new NttContext[this.primes.length];
        for (int i = 0; i < this.primes.length; i++) {
            try {
                ntt[i] = NttContext.create(n, this.primes[i]);
            } catch (RuntimeException e) {
                ntt[i] = null;
            }
        }

        // 两个素数时把 CRT 逆元预先算好（热路径上要调用 2N 次）
        this.crtInv = this.primes.length == 2
            ? RingOps.inverse(this.primes[0] % this.primes[1], this.primes[1])
            : 0;
        // 多素数时同样把每一步的逆元预算好，避免在热路径里做 modInverse
        this.crtStepInv = new BigInteger[this.primes.length];
        BigInteger running = BigInteger.ONE;
        for (int k = 0; k < this.primes.length; k++) {
            if (k == 0) {
                running = BigInteger.valueOf(this.primes[0]);
                continue;
            }
            BigInteger mk = BigInteger.valueOf(this.primes[k]);
            crtStepInv[k] = running.mod(mk).modInverse(mk);
            running = running.multiply(mk);
        }
    }

    /** 该参数是否全程可用 NTT */
    public boolean nttEnabled() {
        for (NttContext c : ntt) {
            if (c == null) {
                return false;
            }
        }
        return true;
    }

    /** 解密允许的噪声上限（相位单位）：q / (2t) */
    public BigInteger noiseLimit() {
        return q.divide(BigInteger.valueOf(2 * t));
    }

    /** 按位宽直接算层数：取满足 base^levels > q 的最小值（不用累乘循环，避免溢出） */
    public static int autoLevels(int base, BigInteger q) {
        int levels = 1;
        BigInteger cap = BigInteger.valueOf(base);
        while (cap.compareTo(q) <= 0) {
            cap = cap.multiply(BigInteger.valueOf(base));
            levels++;
        }
        return levels;
    }

    /**
     * 快测参数：单个 NTT 友好素数、N=1024、小基数多层级。
     * 噪声余量大、跑得快，适合反复迭代调试结构。
     */
    public static RingParams lab() {
        long prime = NttContext.findPrime(31, 1024, 0);
        return new RingParams("lab", 1024, new long[]{prime}, 65537L, 4, 16, 4);
    }

    /**
     * 论文级参数：能表达的部分全部按论文取。
     * <ul>
     *   <li>t = 65537 ← 论文</li>
     *   <li>gadget 基数 = 2^16（与 MPC4J 的 C++ 实现一致）</li>
     *   <li>系数模数用 {@code primeCount} 个约 31 位素数；论文是 9 个素数共 438 位，
     *       本实验用 15 个素数可到约 465 位，量级一致</li>
     *   <li>层数 l 按 B^l &gt; q 自动取</li>
     * </ul>
     *
     * @param n          多项式次数；论文为 16384
     * @param primeCount 素数个数（论文等价规模取 15）
     */
    public static RingParams paperParams(int n, int primeCount) {
        long[] primes = new long[primeCount];
        long cursor = 0;
        for (int i = 0; i < primeCount; i++) {
            // NTT 友好的素数（满足 2N | p-1）；从上一个之后继续找，避免重复
            primes[i] = NttContext.findPrime(31, n, cursor);
            cursor = primes[i] - (1L << 30) + 1;
        }
        return new RingParams("paper-like", n, primes, 65537L, 1 << 16,
            autoLevels(1 << 16, product(primes)), 4);
    }

    private static BigInteger product(long[] primes) {
        BigInteger p = BigInteger.ONE;
        for (long v : primes) {
            p = p.multiply(BigInteger.valueOf(v));
        }
        return p;
    }

    /** 每个素数的位宽（用于日志） */
    public String primesInfo() {
        StringBuilder sb = new StringBuilder();
        for (long p : primes) {
            sb.append(64 - Long.numberOfLeadingZeros(p)).append(' ');
        }
        return sb.toString().trim();
    }

    public String describe() {
        return String.format(
            "preset=%s, N=%d, primes=%d [%s], q=%d bit, t=%d, delta=%d bit, base=%d, levels=%d, noiseBits=%d",
            name, n, primes.length, primesInfo(), qBits, t, delta.bitLength(), base, levels, noiseBits);
    }
}
