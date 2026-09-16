package com.fusepir.rlwe;

/**
 * 一个 RLWE 密文：两个多项式 (c0, c1)，相位 = c0 + c1 * s。
 *
 * <p>每个多项式都是 [素数下标][系数] 的形状。
 *
 * <p>消息在哪一段：
 * <ul>
 *   <li>把明文加到 <b>c0</b> 上，相位就 +明文；</li>
 *   <li>把明文加到 <b>c1</b> 上，相位就 +明文·s。</li>
 * </ul>
 * RGSW 的两组密文正是靠这个区别构造出来的。
 */
public final class RlweCiphertext {
    public final long[][] c0;
    public final long[][] c1;

    public RlweCiphertext(long[][] c0, long[][] c1) {
        this.c0 = c0;
        this.c1 = c1;
    }
}
