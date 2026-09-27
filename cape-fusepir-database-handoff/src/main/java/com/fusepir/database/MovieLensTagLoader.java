package com.fusepir.database;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public final class MovieLensTagLoader {
    private MovieLensTagLoader() {}

    /** 载入全部关键词 */
    public static CanonicalDatabase load(Path tagsCsv) throws IOException {
        return load(tagsCsv, Integer.MAX_VALUE);
    }

    /**
     * 载入前 {@code maxKeywords} 个关键词（按字典序取前 N 个，结果可复现）。
     *
     * <p><b>为什么需要它</b>：载荷长度是 {@code 3 + 2 + m·(2+ℓ_BF)}，其中
     * {@code m = maxKeywords 里单个关键词关联的 value 数上界}。真实 MovieLens small 的
     * {@code m = 131}，于是每个关键词都要填充到 131 个 value —— 即使平均只有 2.42 个。
     * 这让 BFF 表规模变成 {@code O(n · m · ℓ_BF)}，光明文就 GB 级。
     *
     * <p>测试阶段（只验证原理能否跑通）用一个小子集即可：{@code m} 随之降到个位数，
     * 整条链路能在秒级、MB 级跑完。**缩的是规模，不是结构** —— k=3 位置、分段 BFF、
     * 指纹判定、ℓ ≤ N 这些约束都不变，所以原理结论对论文参数同样成立。
     *
     * @param maxKeywords 关键词数上限；取字典序最小的前若干个，保证可复现
     */
    public static CanonicalDatabase load(Path tagsCsv, int maxKeywords) throws IOException {
        if (maxKeywords < 1) throw new IllegalArgumentException("maxKeywords must be positive");
        Map<String, Set<Integer>> forward = new TreeMap<>();
        try (var reader = Files.newBufferedReader(tagsCsv, StandardCharsets.UTF_8)) {
            String line = reader.readLine();
            if (line == null) return new CanonicalDatabase(List.of(), Map.of(), 0, 32);
            while ((line = reader.readLine()) != null) {
                List<String> fields = parseCsvLine(line);
                if (fields.size() < 3) continue;
                String keyword = TagCanonicalizer.canonicalize(fields.get(2));
                if (keyword.isEmpty()) continue;
                int movieId = Integer.parseUnsignedInt(fields.get(1).trim());
                forward.computeIfAbsent(keyword, ignored -> new TreeSet<>()).add(movieId);
            }
        }

        // 抽样：取字典序最小的前 maxKeywords 个关键词，值取每个关键词自身关联的（不裁剪）
        Map<String, Set<Integer>> sampled = new TreeMap<>();
        for (Map.Entry<String, Set<Integer>> entry : forward.entrySet()) {
            if (sampled.size() >= maxKeywords) break;
            sampled.put(entry.getKey(), entry.getValue());
        }

        Map<Integer, Set<String>> reverse = new TreeMap<>();
        sampled.forEach((keyword, values) ->
            values.forEach(movieId -> reverse.computeIfAbsent(movieId, ignored -> new TreeSet<>()).add(keyword)));

        List<KeywordRecord> records = sampled.entrySet().stream()
                .map(e -> new KeywordRecord(e.getKey(), e.getValue().stream().mapToInt(Integer::intValue).toArray()))
                .toList();
        int maxValues = records.stream().mapToInt(r -> r.values().length).max().orElse(0);
        return new CanonicalDatabase(records, reverse, maxValues, 32);
    }

    private static List<String> parseCsvLine(String line) {
        List<String> result = new ArrayList<>(); StringBuilder field = new StringBuilder(); boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') { if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') field.append('"'); else quoted = !quoted; }
            else if (c == ',' && !quoted) { result.add(field.toString()); field.setLength(0); }
            else field.append(c);
        }
        result.add(field.toString()); return result;
    }
}
