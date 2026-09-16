package com.fusepir.database;

import java.util.Arrays;

public record KeywordRecord(String keyword, int[] values) {
    public KeywordRecord {
        if (keyword == null || keyword.isBlank()) throw new IllegalArgumentException("keyword is blank");
        values = values.clone();
        for (int i = 1; i < values.length; i++) {
            if (values[i] <= values[i - 1]) throw new IllegalArgumentException("values must be strictly ascending");
        }
    }

    @Override public int[] values() { return values.clone(); }

    @Override public boolean equals(Object other) {
        return other instanceof KeywordRecord r && keyword.equals(r.keyword) && Arrays.equals(values, r.values);
    }

    @Override public int hashCode() { return 31 * keyword.hashCode() + Arrays.hashCode(values); }
}
