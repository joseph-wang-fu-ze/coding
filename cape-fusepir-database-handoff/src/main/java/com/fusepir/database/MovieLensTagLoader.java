package com.fusepir.database;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public final class MovieLensTagLoader {
    private MovieLensTagLoader() {}

    public static CanonicalDatabase load(Path tagsCsv) throws IOException {
        Map<String, Set<Integer>> forward = new TreeMap<>();
        Map<Integer, Set<String>> reverse = new TreeMap<>();
        try (var reader = Files.newBufferedReader(tagsCsv, StandardCharsets.UTF_8)) {
            String line = reader.readLine();
            if (line == null) return new CanonicalDatabase(List.of(), Map.of(), 0, 32);
            while ((line = reader.readLine()) != null) {
                List<String> fields = parseCsvLine(line);
                if (fields.size() < 3) continue;
                String keyword = TagCanonicalizer.canonicalize(fields.get(2));
                if (keyword.isEmpty()) continue;
                int movieId = Integer.parseUnsignedInt(fields.get(1).trim());
                if (forward.computeIfAbsent(keyword, ignored -> new TreeSet<>()).add(movieId))
                    reverse.computeIfAbsent(movieId, ignored -> new TreeSet<>()).add(keyword);
            }
        }
        List<KeywordRecord> records = forward.entrySet().stream()
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
