package com.fusepir.rlwe;

import java.math.BigInteger;
import java.util.Random;

/**
 * RLWE 的编解码、加解密与相位计算。
 *
 * <h3>两类加密</h3>
 * <ul>
 *   <li><b>带缩放的加密</b>（{@link #encryptScaled}）：消息 m ∈ Z_t，相位 = Δ·m + 噪声。
 *       普通密文（客户端查询、载荷）用它。</li>
 *   <li><b>原始加密</b>（{@link #encryptRaw}）：消息是 Z_q 上的多项式，直接加到 c0 上、不做缩放。
 *       RGSW 的两组密文用它——与 MPC4J 的 C++ 实现一致。</li>
 * </ul>
 *
 * <p>各素数下的多项式运算全部用 long（素数 &lt; 2^31，乘积不溢出）；
 * 只有"整数值"（编码后的消息、还原后的相位）用大整数，因为素数较多时 q 远超 64 位。
 */
public final class RlweOps {

    private RlweOps() {
    }

    /**
     * 把 Z_t 上的消息编码成缩放后的整数值：c = round(m · q / t)（再对 q 取模）。
     *
     * <p>注意必须用<b>真实比值 q/t</b>（带小数），不能用整数除法向下取整的 Δ，
     * 否则每经过一个消息系数就差一点、累计到 m 接近 t 时解码会整体偏移（实测踩过）。
     */
    public static BigInteger[] encodeScaledValues(RingParams p, long[] m) {
        BigInteger t = BigInteger.valueOf(p.t);
        BigInteger half = t.shiftRight(1);
        BigInteger[] out = new BigInteger[p.n];
        for (int i = 0; i < p.n; i++) {
            long v = ((m[i] % p.t) + p.t) % p.t;
            out[i] = BigInteger.valueOf(v).multiply(p.q).add(half).divide(t).mod(p.q);
        }
        return out;
    }

    /** 带缩放的加密：消息 m ∈ Z_t，直接构造成各素数下的多项式 */
    public static RlweCiphertext encryptScaled(RingParams p, RlweKey key, long[] m, Random rnd) {
        return encryptRawPrime(p, key, RingOps.toPrimePoly(p, encodeScaledValues(p, m)), rnd);
    }

    /** 原始加密：消息是 [0, q) 上的整数值，直接加到 c0 上，不做缩放 */
    public static RlweCiphertext encryptRaw(RingParams p, RlweKey key, BigInteger[] msg, Random rnd) {
        return encryptRawPrime(p, key, RingOps.toPrimePoly(p, msg), rnd);
    }

    /** 原始加密（已按素数拆好的消息多项式版本，RGSW 内部用） */
    public static RlweCiphertext encryptRawPrime(RingParams p, RlweKey key, long[][] mPoly, Random rnd) {
        long[][] a = RingOps.sampleUniform(rnd, p);
        long[][] e = RingOps.sampleNoise(rnd, p);
        long[][] as = key.mul(p, a); // 私钥乘法：走已缓存的私钥 NTT
        long[][] c0 = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            long prime = p.primes[k];
            for (int i = 0; i < p.n; i++) {
                // c0 = -a*s + e + M
                long v = RingOps.subMod(mPoly[k][i], as[k][i], prime);
                c0[k][i] = RingOps.addMod(v, e[k][i], prime);
            }
        }
        return new RlweCiphertext(c0, a);
    }

    /** 相位 = c0 + c1 * s，还原到 [0, q) 上的整数值 */
    public static BigInteger[] phase(RingParams p, RlweKey key, RlweCiphertext ct) {
        long[][] c1s = key.mul(p, ct.c1);
        long[][] sum = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            for (int i = 0; i < p.n; i++) {
                sum[k][i] = RingOps.addMod(ct.c0[k][i], c1s[k][i], p.primes[k]);
            }
        }
        return RingOps.crtPoly(p, sum);
    }

    /** 解密：v = round(相位 · t / q) mod t，与 {@link #encodeScaledValues} 互为逆运算 */
    public static long[] decrypt(RingParams p, RlweKey key, RlweCiphertext ct) {
        BigInteger[] ph = phase(p, key, ct);
        long[] out = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            out[i] = unscale(p, ph[i]);
        }
        return out;
    }

    /** 相位 → 消息：round(相位 · t / q) mod t */
    public static long unscale(RingParams p, BigInteger phase) {
        BigInteger num = phase.multiply(BigInteger.valueOf(p.t)).add(p.q.shiftRight(1));
        long v = num.divide(p.q).longValueExact();
        return ((v % p.t) + p.t) % p.t;
    }

    /**
     * 噪声大小：|相位 − 编码后的期望消息| 的中心化无穷范数。
     * 一旦超过 {@link RingParams#noiseLimit()}，解密就会出错。
     */
    public static BigInteger noiseNorm(RingParams p, RlweKey key, RlweCiphertext ct, long[] expectedMsg) {
        BigInteger[] ph = phase(p, key, ct);
        BigInteger[] expected = encodeScaledValues(p, expectedMsg);
        BigInteger max = BigInteger.ZERO;
        for (int i = 0; i < p.n; i++) {
            BigInteger d = ph[i].subtract(expected[i]).mod(p.q);
            BigInteger c = RingOps.center(p, d).abs();
            if (c.compareTo(max) > 0) {
                max = c;
            }
        }
        return max;
    }

    /** 把 [0, q) 上的整数值（小值）变成"各素数下的余数"表示 */
    public static long[][] toPrimePoly(RingParams p, long[] values) {
        long[][] out = new long[p.primes.length][p.n];
        for (int k = 0; k < p.primes.length; k++) {
            out[k] = toPrimePolyOne(p, values, k);
        }
        return out;
    }

    /** 同 {@link #toPrimePoly}，用于切段得到的十进制数字（值一定很小，不会超过 q） */
    public static long[][] toPrimePolySmall(RingParams p, long[] values) {
        return toPrimePoly(p, values);
    }

    /** 只归约到某一个素数下（NTT 路径逐素数处理时用） */
    public static long[] toPrimePolyOne(RingParams p, long[] values, int primeIndex) {
        long prime = p.primes[primeIndex];
        long[] out = new long[p.n];
        for (int i = 0; i < p.n; i++) {
            out[i] = ((values[i] % prime) + prime) % prime;
        }
        return out;
    }
}
