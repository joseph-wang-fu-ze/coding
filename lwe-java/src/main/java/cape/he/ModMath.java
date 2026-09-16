package cape.he;

/**
 * 模运算工具。
 *
 * 新手最容易踩的坑在这里:
 * Java 的 long 是有符号的,直接 x + y 可能会溢出成负数,
 * 然后 % q 的结果就变成负数了(Java 的 % 会保留符号)。
 *
 * 本类所有方法都保证返回 [0, q) 区间内的非负值。
 */
public final class ModMath {

    private ModMath() {
    }

    /** 加法:(a + b) mod q,结果在 [0, q) */
    public static long add(long a, long b, long q) {
        long r = a + b;
        // 若 a, b 都在 [0, q) 且 q < 2^63,则 r 不会溢出
        r %= q;
        return r < 0 ? r + q : r;
    }

    /** 减法:(a - b) mod q,结果在 [0, q) */
    public static long sub(long a, long b, long q) {
        long r = (a - b) % q;
        return r < 0 ? r + q : r;
    }

    /** 乘法:(a * b) mod q。用 128 位中间结果避免溢出 */
    public static long mul(long a, long b, long q) {
        // Math.multiplyHigh 需要 Java 9+;这里用 BigInteger-free 的方案:
        // 若 q < 2^31 可直接相乘;否则拆成高低位。
        if (q <= 0x7FFFFFFFL) {
            return ((a * b) % q + q) % q;
        }
        // 128 位乘法取模
        java.math.BigInteger ba = java.math.BigInteger.valueOf(a);
        java.math.BigInteger bb = java.math.BigInteger.valueOf(b);
        java.math.BigInteger bq = java.math.BigInteger.valueOf(q);
        return ba.multiply(bb).mod(bq).longValue();
    }

    /** 取负:(-a) mod q */
    public static long neg(long a, long q) {
        return a == 0 ? 0 : q - a;
    }

    /** 把 x 归一化到 (-q/2, q/2] 的中心化表示 */
    public static long center(long x, long q) {
        long r = ((x % q) + q) % q;
        return r > q / 2 ? r - q : r;
    }

    /**
     * 内积 <lhs, rhs> mod q。
     * 这是 LWE 最核心的运算 —— b = <a, s> + e 就靠它。
     */
    public static long dotProduct(long[] lhs, long[] rhs, long q) {
        if (lhs.length != rhs.length) {
            throw new IllegalArgumentException(
                    "向量长度不一致: " + lhs.length + " vs " + rhs.length);
        }
        long acc = 0;
        for (int i = 0; i < lhs.length; i++) {
            acc = add(acc, mul(lhs[i], rhs[i], q), q);
        }
        return acc;
    }

    /** 逐元素相加:c = a + b mod q(原地写入 result) */
    public static void addEq(long[] a, long[] b, long[] result, long q) {
        for (int i = 0; i < a.length; i++) {
            result[i] = add(a[i], b[i], q);
        }
    }

    /** 逐元素取负:c = -a mod q */
    public static long[] negate(long[] a, long q) {
        long[] out = new long[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = neg(a[i], q);
        }
        return out;
    }
}
