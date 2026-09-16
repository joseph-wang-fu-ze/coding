package com.fusepir.database;

public record CapeParameters(int securityBits, int ringDegreeN, int bffK, int fingerprintBits,
                             double bloomFalsePositiveTarget, int plaintextModulus) {
    public static CapeParameters defaults() { return new CapeParameters(128, 16384, 3, 40, Math.pow(2, -20), 65537); }
}
