package com.fusepir.rlwe;

import java.math.BigInteger;

/**
 * Gadget 分解：把一个 [0, q) 上的整数按 B 进制切成若干段。
 *
 * <p>这是 RGSW、重线性化、密钥切换**共用的底层机制**：
 * <ul>
 *   <li>RGSW 外部乘积：把源密文的系数切段，去乘评估密钥的各层；</li>
 *   <li>重线性化：把三元密文的第三分量切段，去乘"s² 的重线性化密钥"；</li>
 *   <li>密钥切换：把它切段去乘"换密钥后的秘密"的密钥。</li>
 * </ul>
 *
 * <p><b>关键：切段前必须先跨素数还原。</b>输入是 CRT 还原后的整数值，不是某个素数下的余数——
 * 顺序反了会静默算错（实测踩过）。
 */
public final class Gadget {

    private Gadget() {
    }

    /**
     * 按 B 进制把整数值切成 levels 段。
     *
     * @param values CRT 还原后的整数值（每个都在 [0, q)）
     * @return 形状 [层][系数]，每段都小于 B
     */
    public static long[][] decompose(RingParams p, BigInteger[] values, int base, int levels) {
        long[][] digits = new long[levels][p.n];
        BigInteger b = BigInteger.valueOf(base);
        for (int i = 0; i < p.n; i++) {
            BigInteger x = values[i];
            for (int k = 0; k < levels; k++) {
                digits[k][i] = x.mod(b).longValueExact();
                x = x.divide(b);
            }
        }
        return digits;
    }

    /** 切段的逆运算（自检用）：Σ d_k · B^k 必须等于原值 */
    public static BigInteger[] recompose(RingParams p, long[][] digits, int base) {
        BigInteger b = BigInteger.valueOf(base);
        BigInteger[] out = new BigInteger[p.n];
        for (int i = 0; i < p.n; i++) {
            BigInteger x = BigInteger.ZERO;
            for (int k = digits.length - 1; k >= 0; k--) {
                x = x.multiply(b).add(BigInteger.valueOf(digits[k][i]));
            }
            out[i] = x;
        }
        return out;
    }

    /** 覆盖整个 q 所需的最小层数：满足 base^levels > q */
    public static int levelsFor(int base, BigInteger q) {
        return RingParams.autoLevels(base, q);
    }
}
