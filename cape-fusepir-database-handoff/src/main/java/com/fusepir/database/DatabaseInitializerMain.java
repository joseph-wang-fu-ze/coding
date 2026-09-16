package com.fusepir.database;

import java.nio.file.Path;

public final class DatabaseInitializerMain {
    private DatabaseInitializerMain() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("usage: DatabaseInitializerMain <tags.csv>");
        CanonicalDatabase db = MovieLensTagLoader.load(Path.of(args[0]));
        PreparedDatabase prepared = new DatabasePreprocessor().prepare(db, CapeParameters.defaults());
        double average = db.records().stream().mapToInt(r -> r.values().length).average().orElse(0);
        System.out.printf("n=%d |V|=%d m=%d averageValues=%.2f smax=%d h=%d lBF=%d Bpay=%d L_BFF=%d R=%d C=%d%n",
                db.records().size(), db.keywordsByValue().size(), db.maxValues(), average,
                db.keywordsByValue().values().stream().mapToInt(java.util.Set::size).max().orElse(0),
                prepared.bloom().hashCount(), prepared.bloom().length(), prepared.payloadLength(),
                prepared.rows() * prepared.columns(), prepared.rows(), prepared.columns());
    }
}
