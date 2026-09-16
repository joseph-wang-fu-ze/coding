package com.fusepir.database;

import java.util.*;

public record CanonicalDatabase(List<KeywordRecord> records, Map<Integer, Set<String>> keywordsByValue,
                               int maxValues, int valueBits) {
    public CanonicalDatabase {
        records = List.copyOf(records);
        var reverse = new TreeMap<Integer, Set<String>>();
        keywordsByValue.forEach((v, ks) -> reverse.put(v, Set.copyOf(ks)));
        keywordsByValue = Collections.unmodifiableMap(reverse);
        if (maxValues < 0 || valueBits != 32) throw new IllegalArgumentException("invalid database metadata");
    }
}
