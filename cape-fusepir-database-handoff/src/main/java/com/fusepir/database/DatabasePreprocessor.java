package com.fusepir.database;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public final class DatabasePreprocessor implements PlaintextDatabasePreprocessor {
    @Override public PreparedDatabase prepare(CanonicalDatabase db, CapeParameters params) {
        BloomParameters bloom = BloomParameters.choose(db.keywordsByValue().values().stream().mapToInt(Set::size).max().orElse(0), params.bloomFalsePositiveTarget(), params.ringDegreeN());
        int m = db.maxValues();
        int payloadLength = 3 + 2 + m * (2 + bloom.length());
        Map<String, PlaintextPayload> payloads = new TreeMap<>();
        for (KeywordRecord record : db.records()) {
            short[] payload = new short[payloadLength];
            int p = 0; int[] fp = fingerprint(record.keyword());
            for (int x : fp) payload[p++] = (short) x;
            payload[p++] = (short) (record.values().length >>> 16); payload[p++] = (short) record.values().length;
            for (int value : record.values()) {
                payload[p++] = (short) (value >>> 16); payload[p++] = (short) value;
                BitSet bits = bloom(value, db.keywordsByValue().getOrDefault(value, Set.of()), bloom);
                for (int i = 0; i < bloom.length(); i++) payload[p++] = (short) (bits.get(i) ? 1 : 0);
            }
            payloads.put(record.keyword(), new PlaintextPayload(record.keyword(), payload));
        }
        int L = Math.max(payloadLength, db.records().size());
        int rows = Math.min(params.ringDegreeN(), Math.max(1, (int) Math.ceil(Math.sqrt(L))));
        int columns = (int) Math.ceil((double) L / rows);
        return new PreparedDatabase(payloads, bloom, m, payloadLength, rows, columns);
    }

    private static int[] fingerprint(String keyword) {
        byte[] digest = digest(keyword); return new int[]{u16(digest, 0), u16(digest, 2), u16(digest, 4)};
    }
    private static BitSet bloom(int value, Set<String> keywords, BloomParameters p) {
        BitSet bits = new BitSet(p.length());
        for (String keyword : keywords) { byte[] d = digest(keyword + ":" + value); for (int i = 0; i < p.hashCount(); i++) bits.set(Math.floorMod(intAt(d, i * 4), p.length())); }
        return bits;
    }
    private static byte[] digest(String value) { try { return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); } catch (Exception e) { throw new IllegalStateException(e); } }
    private static int u16(byte[] b, int p) { return ((b[p] & 255) << 8) | (b[p + 1] & 255); }
    private static int intAt(byte[] b, int p) { p %= b.length - 3; return (b[p] & 255) << 24 | (b[p + 1] & 255) << 16 | (b[p + 2] & 255) << 8 | b[p + 3] & 255; }
}
