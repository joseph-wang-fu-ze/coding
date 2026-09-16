package com.fusepir.database;

public record BloomParameters(int hashCount, int length) {
    public static BloomParameters choose(int maxSetSize, double target, int maxLength) {
        if (maxSetSize == 0) return new BloomParameters(1, 1);
        BloomParameters best = null;
        for (int h = 1; h <= 16; h++) {
            int length = (int) Math.ceil(-h * maxSetSize / Math.log(1 - Math.pow(target, 1.0 / h)));
            if (best == null || length < best.length) best = new BloomParameters(h, length);
        }
        if (best.length > maxLength) throw new IllegalArgumentException("Bloom length exceeds ring dimension: " + best.length);
        return best;
    }
}
