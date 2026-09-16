package com.fusepir.rlwe;

import java.math.BigInteger;
import java.util.Random;

/**
 * 重线性化密钥（RelinKeys）：把"三元密文"降回"二元密文"用的评估材料。
 *
 * <h3>为什么需要</h3>
 * 密文 × 密文 会把相位变成 c0 + c1·s + <b>c2·s²</b>（三元）。不降回来，
 * 再乘一次就变四元、五元……无法收敛。
 *
 * <h3>构造（就是 gadget 那一套）</h3>
 * 对每一层 j，造一个相位为 <b>T^j · s²</b> 的 RLWE 密文：
 * <pre>
 *   采样均匀 a、噪声 e，令 c1 = a，c0 = -a⊛s + e + T^j·(s⊛s)
 *   于是相位 = c0 + c1·s = e + T^j·s²
 * </pre>
 * 注意 T 的层数必须满足 {@code T^levels > q}，否则切段覆盖不全、结果静默出错。
 *
 * <h3>应用（见 {@link CiphertextOps#relinearize}）</h3>
 * 把 c2 切段成 d_j，令
 * <pre>
 *   c0' = c0 + Σ d_j ⊛ b_j ,   c1' = c1 + Σ d_j ⊛ a_j
 *   phase(c0', c1') = c0 + c1 s + Σ d_j (b_j + a_j s) = c0 + c1 s + (Σ d_j T^j) s²
 *                   = c0 + c1 s + c2 s²        ✓
 * </pre>
 * 即"用公开的切段数字，去乘加密的 s²"——和 RGSW 外部乘积是同一个套路。
 */
public final class RelinKeys {
    /** 分解基数 T */
    public final int base;
    /** 层数（必须满足 T^levels > q） */
    public final int levels;
    /** 每层一个密文：相位 = T^j · s² */
    public final RlweCiphertext[] keys;

    private RelinKeys(int base, int levels, RlweCiphertext[] keys) {
        this.base = base;
        this.levels = levels;
        this.keys = keys;
    }

    /**
     * 生成重线性化密钥。
     *
     * @param base   分解基数（建议 2^16，与 gadget 一致）
     * @param levels 层数；传 0 表示自动取满足 base^levels &gt; q 的最小值
     */
    public static RelinKeys generate(RingParams p, RlweKey key, int base, int levels, Random rnd) {
        int l = levels > 0 ? levels : Gadget.levelsFor(base, p.q);
        // s² = s ⊛ s
        long[][] s2 = RingOps.mul(key.s, key.s, p);

        RlweCiphertext[] keys = new RlweCiphertext[l];
        BigInteger power = BigInteger.ONE;
        BigInteger b = BigInteger.valueOf(base);
        for (int j = 0; j < l; j++) {
            long[][] msg = RingOps.scalarMulBig(s2, power, p); // T^j · s²
            keys[j] = RlweOps.encryptRawPrime(p, key, msg, rnd);
            power = power.multiply(b);
        }
        return new RelinKeys(base, l, keys);
    }

    /** 密钥体积（字节）：levels 个 RLWE 密文 */
    public long bytes(RingParams p) {
        long perCoefficient = (p.qBits + 7L) / 8L;
        return (long) levels * 2L * p.n * perCoefficient;
    }

    public String describeBytes(RingParams p) {
        long b = bytes(p);
        if (b < (1L << 20)) {
            return String.format("%.1f KB", b / 1024.0);
        }
        if (b < (1L << 30)) {
            return String.format("%.1f MB", b / 1048576.0);
        }
        return String.format("%.2f GB", b / 1073741824.0);
    }
}
