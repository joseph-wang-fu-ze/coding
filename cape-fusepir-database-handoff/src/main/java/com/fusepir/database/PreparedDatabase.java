package com.fusepir.database;

import java.util.Map;

public record PreparedDatabase(Map<String, PlaintextPayload> payloads, BloomParameters bloom,
                               int maxValueCount, int payloadLength, int rows, int columns) {
    public PreparedDatabase { payloads = Map.copyOf(payloads); }
}
