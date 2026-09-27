package com.fusepir.database;

import java.nio.file.Path;
import java.util.*;

/** 列出载入后的关键词，便于挑选端到端测试的查询词。 */
public final class ListKeywordsMain {
    private ListKeywordsMain() {}

    public static void main(String[] args) throws Exception {
        Path tags = Path.of(args[0]);
        int limit = args.length > 1 ? Integer.parseInt(args[1]) : 32;
        CanonicalDatabase db = MovieLensTagLoader.load(tags, limit);
        System.out.printf("载入 %d 个关键词, %d 个值, m=%d%n%n",
            db.records().size(), db.keywordsByValue().size(), db.maxValues());
        for (KeywordRecord r : db.records()) {
            System.out.printf("  %-24s %d 个值: %s%n",
                r.keyword(), r.values().length,
                r.values().length <= 8 ? Arrays.toString(r.values()) : "(" + r.values().length + " 个)");
        }
    }
}
