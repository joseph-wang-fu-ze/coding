package com.fusepir.database;

import java.nio.file.Path;

/**
 * 数据库初始化诊断：打印一组 CAPE 参数下的明文侧规模。
 *
 * <pre>
 *   DatabaseInitializerMain &lt;tags.csv&gt;                     论文参数 + 全量数据
 *   DatabaseInitializerMain &lt;tags.csv&gt; test                最小参数 + 全量数据
 *   DatabaseInitializerMain &lt;tags.csv&gt; test 32             最小参数 + 前 32 个关键词
 *   DatabaseInitializerMain &lt;tags.csv&gt; paper 200           论文参数 + 前 200 个关键词
 * </pre>
 *
 * <p>规模由三者相乘决定：{@code L_BFF × payloadLength}，而
 * {@code payloadLength = 3 + 2 + m·(2+ℓ_BF)}。所以要真正变小，<b>数据集也要抽样</b>
 * —— 真实 MovieLens small 的 {@code m=131} 会让每个关键词都填充到 131 个 value。
 */
public final class DatabaseInitializerMain {

    private DatabaseInitializerMain() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 3) {
            throw new IllegalArgumentException(
                "usage: DatabaseInitializerMain <tags.csv> [paper|test] [maxKeywords]");
        }
        CapeParameters parameters = args.length >= 2
            ? switch (args[1].toLowerCase()) {
                case "test" -> CapeParameters.testMinimal();
                case "paper" -> CapeParameters.paperAligned();
                default -> throw new IllegalArgumentException("unknown preset: " + args[1]);
              }
            : CapeParameters.paperAligned();
        int maxKeywords = args.length == 3 ? Integer.parseInt(args[2]) : Integer.MAX_VALUE;

        CanonicalDatabase db = maxKeywords == Integer.MAX_VALUE
            ? MovieLensTagLoader.load(Path.of(args[0]))
            : MovieLensTagLoader.load(Path.of(args[0]), maxKeywords);
        PayloadBlockProvider provider = PayloadBlockProvider.from(db, parameters, DatabasePreprocessor.DEFAULT_FINGERPRINT_SEED);
        PayloadLayout payload = provider.layout();

        double average = db.records().stream().mapToInt(r -> r.values().length).average().orElse(0);
        int bffLength = ArithmeticBffEncoder.tableLength(db.records().size());

        System.out.println("[preset] " + (args.length >= 2 ? args[1] : "paper")
            + (maxKeywords == Integer.MAX_VALUE ? "" : " , 关键词上限=" + maxKeywords)
            + "  " + parameters.describe());
        System.out.printf("n=%d |V|=%d m=%d averageValues=%.2f smax=%d h=%d lBF=%d Bpay=%d L_BFF=%d%n",
                db.records().size(), db.keywordsByValue().size(), db.maxValues(), average,
                db.keywordsByValue().values().stream().mapToInt(java.util.Set::size).max().orElse(0),
                payload.bloom().hashCount(), payload.bloom().length(), payload.payloadLength(),
                bffLength);
        System.out.println("[scale] " + provider.describe());
    }
}
