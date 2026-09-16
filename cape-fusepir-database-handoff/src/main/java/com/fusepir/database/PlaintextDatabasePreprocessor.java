package com.fusepir.database;

public interface PlaintextDatabasePreprocessor {
    PreparedDatabase prepare(CanonicalDatabase db, CapeParameters params);
}
