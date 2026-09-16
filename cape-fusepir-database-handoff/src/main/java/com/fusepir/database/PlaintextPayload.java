package com.fusepir.database;

public record PlaintextPayload(String keyword, short[] coefficients) {
    public PlaintextPayload { coefficients = coefficients.clone(); }
    @Override public short[] coefficients() { return coefficients.clone(); }
}
