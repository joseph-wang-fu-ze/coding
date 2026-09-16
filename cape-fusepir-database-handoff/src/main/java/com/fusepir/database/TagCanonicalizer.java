package com.fusepir.database;

import java.text.Normalizer;
import java.util.Locale;

public final class TagCanonicalizer {
    private TagCanonicalizer() {}

    public static String canonicalize(String raw) {
        if (raw == null) return "";
        return Normalizer.normalize(raw, Normalizer.Form.NFC)
                .trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
    }
}
