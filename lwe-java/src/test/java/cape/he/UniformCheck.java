package cape.he;

import java.util.Random;

/** Minimal check: is the uniform sampler in LWE actually returning non-zero values? */
public final class UniformCheck {

    public static void main(String[] args) {
        Random rnd = new Random(12345L);

        System.out.println("--- raw Random.nextLong() & mask ---");
        long q = 1L << 32;
        long mask = q - 1;
        int zeros = 0;
        for (int i = 0; i < 8; i++) {
            long v = rnd.nextLong() & mask;
            System.out.printf("  nextLong()&mask = %d (0x%x)%n", v, v);
            if (v == 0) zeros++;
        }

        System.out.println();
        System.out.println("--- via LWE.nextUniform ---");
        LWEParams p = LWEParams.withDefaults();
        LWE lwe = new LWE(p, new Random(12345L));
        zeros = 0;
        for (int i = 0; i < 8; i++) {
            long v = lwe.nextUniform(q);
            System.out.printf("  nextUniform(q) = %d (0x%x)%n", v, v);
            if (v == 0) zeros++;
        }

        System.out.println();
        System.out.println("--- the actual a vector from an encryption ---");
        LWESecretKey sk = lwe.keyGen();
        System.out.println("  sk = " + sk);
        LWECiphertext ct = lwe.encrypt(sk, 0);
        long[] a = ct.getA();
        System.out.printf("  a.length = %d%n", a.length);
        System.out.printf("  a[0..5] = %d %d %d %d %d %d%n",
                a[0], a[1], a[2], a[3], a[4], a[5]);
        int nonzero = 0;
        for (long v : a) {
            if (v != 0) nonzero++;
        }
        System.out.printf("  non-zero components in a: %d / %d%n", nonzero, a.length);

        System.out.println();
        System.out.println("--- dot product <a, s> ---");
        long dot = ModMath.dotProduct(a, sk.getS(), q);
        System.out.printf("  <a,s> = %d%n", dot);
        System.out.printf("  b - <a,s> mod q = %d%n", ModMath.sub(ct.getB(), dot, q));
        System.out.println("  (should equal the error term e, roughly small)");
    }
}
