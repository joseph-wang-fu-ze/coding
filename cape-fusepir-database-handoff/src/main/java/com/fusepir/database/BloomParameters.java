package com.fusepir.database;

/**
 * Bloom 过滤器参数：(hashCount, length)。
 *
 * <p>{@link #choose} 扫 h = 1..16，取使长度最小的最优 (h, ℓ)。
 *
 * <h3>长度上限用谁：{@code maxLength} 是环维度 N，不是 ℓ_BF</h3>
 * 论文把 {ℓ_BF, G} 列为"公共 Bloom 参数"（算法 5 第 1 行），但对本实现而言
 * **真正的硬约束是"一个 value 的 Bloom 位必须装进一个多项式槽位"**，
 * 即 {@code ℓ ≤ N}。{@code maxLength} 传的就是 N（见
 * {@link PayloadBlockProvider#from} / {@link PlaintextFusePirQuery}）。
 *
 * <p>所以 Bloom 假阳性率不能无限压低：{@code ℓ} 会随 {@code -log(ε)} 增长，
 * 撞到 N 就只能抛异常。测试性代码请用 {@link CapeParameters#testMinimal()}。
 */
public record BloomParameters(int hashCount, int length) {

    /**
     * 选出最优 (h, ℓ)。
     *
     * @param maxSetSize 单个 value 关联的关键词数上界（论文里的构造是"每个 value 一个 Bloom 过滤器，
     *                   里面装该 value 的所有关键词"）
     * @param target     目标假阳性率 ε_BF（论文取 2^-20）
     * @param maxLength  长度上限，实际传的是环维度 N
     */
    public static BloomParameters choose(int maxSetSize, double target, int maxLength) {
        if (maxSetSize == 0) return new BloomParameters(1, 1);
        if (!(target > 0) || target >= 1) throw new IllegalArgumentException("target must be in (0,1): " + target);
        BloomParameters best = null;
        for (int h = 1; h <= 16; h++) {
            int length = (int) Math.ceil(-h * maxSetSize / Math.log(1 - Math.pow(target, 1.0 / h)));
            if (best == null || length < best.length) best = new BloomParameters(h, length);
        }
        if (best.length > maxLength) {
            throw new IllegalArgumentException(String.format(
                "Bloom 长度 %d 超过上限 %d：请放宽 bloomFalsePositiveTarget，或提高环维度 N。"
                    + "（maxSetSize=%d, target=2^%.1f）",
                best.length, maxLength, maxSetSize, Math.log(target) / Math.log(2)));
        }
        return best;
    }

    /**
     * 位位置推导：<b>只依赖关键词</b>，不依赖 value。
     *
     * <p>这是与论文对齐的关键（CAPE §4.1 的 Bloom 合取判定）：
     * 客户端查询时只有关键词 {@code K_2..K_Q}，它必须能独立算出这些关键词的位；
     * 服务端某个候选 value 的 Bloom 里装的是"关联到该 value 的关键词"的位。
     * 两边**必须用同一个 {@code B(keyword)}** 才能做内积判定。
     *
     * <p>⚠️ 早期实现写的是 {@code digest(keyword + ":" + value)} —— 把 value 混进了哈希，
     * 导致同一位关键词在不同 value 下落在不同位置，客户端的 b_qry 与服务端的 b_v
     * <b>位位置对不上，内积恒为 0</b>，合取判定永远失败。已在 README 第 11 项记录。
     */
    public boolean[] bits(String keyword) {
        byte[] digest = PayloadFingerprint.sha256(keyword.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        boolean[] bits = new boolean[length];
        for (int index = 0; index < hashCount; index++) {
            bits[Math.floorMod(intAt(digest, index * Integer.BYTES), length)] = true;
        }
        return bits;
    }

    /** 一个 value 的 Bloom：把它关联的每个关键词的位都置上 */
    public boolean[] bits(java.util.Collection<String> keywords) {
        boolean[] bits = new boolean[length];
        for (String keyword : keywords) {
            boolean[] single = bits(keyword);
            for (int index = 0; index < length; index++) {
                if (single[index]) bits[index] = true;
            }
        }
        return bits;
    }

    private static int intAt(byte[] bytes, int offset) {
        int start = Math.floorMod(offset, bytes.length - Integer.BYTES + 1);
        return java.nio.ByteBuffer.wrap(bytes, start, Integer.BYTES).getInt();
    }
}
