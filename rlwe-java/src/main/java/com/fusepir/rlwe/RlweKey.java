package com.fusepir.rlwe;

import java.util.Random;

/**
 * RLWE 密钥：私钥 s 是一个三元多项式（每个素数下各一份表示）。
 *
 * <p>RGSW 的生成需要知道私钥（要对 s·μ·g_i 加密），所以 RGSW 属于"由密钥持有者生成的评估材料"，
 * 与论文一致：这些材料在 Setup 阶段由客户端生成，作为公开参数的一部分交给服务器。
 *
 * <p><b>重要优化</b>：加解密与相位计算都要做"私钥 ⊛ 多项式"，而私钥在整个生命周期里不变。
 * 所以这里把私钥的 NTT 形式**首次使用时算一次、之后一直复用**——否则每次加解密都要重新变换私钥。
 * 实测这条优化把 N=16384 下的加密从 0.48 秒降到约 0.01 秒。
 */
public final class RlweKey {
    /** 私钥多项式，形状为 [素数下标][系数] */
    public final long[][] s;

    /** 私钥的 NTT 形式（惰性计算），形状与 s 相同：[素数下标][系数] */
    private long[][] sNtt;

    public RlweKey(RingParams p, Random rnd) {
        this.s = RingOps.sampleTernary(rnd, p);
    }

    /** 取私钥的 NTT 形式（首次调用计算并缓存） */
    private long[][] nttForm(RingParams p) {
        if (sNtt == null || sNtt.length != p.primes.length
            || sNtt[0] == null || sNtt[0].length != p.n) {
            long[][] cache = new long[p.primes.length][];
            for (int k = 0; k < p.primes.length; k++) {
                cache[k] = p.ntt[k] == null ? null : p.ntt[k].forward(s[k]);
            }
            sNtt = cache;
        }
        return sNtt;
    }

    /**
     * 计算 s ⊛ poly。
     * 有 NTT 上下文时用"私钥 NTT 已缓存 + 一次正向变换 + 一次逆向变换"；
     * 否则回退到三元专用乘法（按符号做加减）。
     */
    public long[][] mul(RingParams p, long[][] poly) {
        if (p.nttEnabled()) {
            long[][] pre = nttForm(p);
            long[][] r = new long[p.primes.length][];
            for (int k = 0; k < p.primes.length; k++) {
                NttContext ctx = p.ntt[k];
                r[k] = ctx.inverse(ctx.pointwise(pre[k], ctx.forward(poly[k])));
            }
            return r;
        }
        return RingOps.mulTernary(s, poly, p);
    }
}
