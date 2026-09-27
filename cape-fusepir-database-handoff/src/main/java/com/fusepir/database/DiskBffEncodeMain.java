package com.fusepir.database;

import java.nio.file.Path;
import java.util.*;

/**
 * 有界内存的 BFF 编码（把矩阵多项式写到磁盘）。
 *
 * <pre>
 *   DiskBffEncodeMain &lt;tags.csv&gt; &lt;empty-output-directory&gt; [block-size] [keyword-limit]
 * </pre>
 *
 * <p><b>默认参数已改成最小测试参数</b>（见 {@link CapeParameters#defaults()}）：
 * 目的是先把原理跑通，不是出论文数字。
 * 环境变量可临时覆盖（不用改代码）：
 * <pre>
 *   CAPE_PRESET=paper   切换到论文参数（表会到 GB 级，慎用）
 * </pre>
 *
 * <p>{@code keyword-limit} 对数据集抽样：载荷长度是
 * {@code 3 + 2 + m·(2+ℓ_BF)}，而真实 MovieLens small 的 {@code m=131}
 * 会让每个关键词都填充到 131 个 value —— 这才是规模的主要来源。
 * 实测前 32 个关键词时整表只要 0.1 MB（论文参数 + 全量是 5196 MB）。
 */
public final class DiskBffEncodeMain {
    private DiskBffEncodeMain() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length > 4) {
            throw new IllegalArgumentException(
                "usage: DiskBffEncodeMain <tags.csv> <empty-output-directory> [block-size] [keyword-limit]");
        }
        int blockSize = args.length >= 3 ? Integer.parseInt(args[2]) : 2048;
        int keywordLimit = args.length >= 4 ? Integer.parseInt(args[3]) : Integer.MAX_VALUE;

        CapeParameters parameters = "paper".equalsIgnoreCase(System.getenv("CAPE_PRESET"))
            ? CapeParameters.paperAligned() : CapeParameters.defaults();
        CanonicalDatabase database = keywordLimit == Integer.MAX_VALUE
            ? MovieLensTagLoader.load(Path.of(args[0]))
            : MovieLensTagLoader.load(Path.of(args[0]), keywordLimit);

        System.out.println("[params] " + parameters.describe()
            + (keywordLimit == Integer.MAX_VALUE ? " + 全量数据" : " + 关键词上限 " + keywordLimit));
        System.out.printf("[db] 关键词=%d, 值=%d, m=%d%n",
            database.records().size(), database.keywordsByValue().size(), database.maxValues());

        long t0 = System.nanoTime();
        DiskBffEncoding encoding = new DiskBffEncoder().encode(
            database, parameters, BffOptions.random(), Path.of(args[1]), blockSize);
        double seconds = (System.nanoTime() - t0) / 1e9;

        System.out.printf("BFF complete: directory=%s L_BFF=%d Bpay=%d R=%d C=%d blocks=%d (%.1f s)%n",
            encoding.directory(), encoding.tableLength(), encoding.payloadLength(),
            encoding.rows(), encoding.columns(), encoding.blockCount(), seconds);
    }
}
