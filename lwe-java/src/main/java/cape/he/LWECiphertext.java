package cape.he;

import java.util.Arrays;

/**
 * LWE 密文 ct = (a, b)。
 *
 * 数学形式:
 *     a ∈ Z_q^d      向量(公开)
 *     b = <a, s> + Delta * m + e   (mod q)   标量
 *
 * 解密:先算 phase = b - <a, s> mod q,
 *       再把它中心化,四舍五入到最近的 Delta 倍数,除以 Delta 即得 m。
 */
public final class LWECiphertext {

    /** a 分量,长度 = 参数中的 dimension */
    private final long[] a;

    /** b 分量 */
    private final long b;

    /** 密文模数 q */
    private final long modulus;

    /** 明文模数 t */
    private final int plaintextModulus;

    public LWECiphertext(long[] a, long b, long modulus, int plaintextModulus) {
        this.a = a;
        this.b = b;
        this.modulus = modulus;
        this.plaintextModulus = plaintextModulus;
    }

    public long[] getA() {
        return a;
    }

    public long getB() {
        return b;
    }

    public long getModulus() {
        return modulus;
    }

    public int getPlaintextModulus() {
        return plaintextModulus;
    }

    /** 向量维度 d —— 盲旋转时要循环 d 次做 CMUX */
    public int dimension() {
        return a.length;
    }

    /**
     * 模数切换:把密文整体映射到新的模数(连接 LWE 层与 RLWE 层的桥梁)。
     *
     * 逐分量做 round(x * q' / q)。用大整数算,不用 double:
     * a[i] 最大可达 2^32,乘上新模数会超过 double 的 53 位尾数 -> 舍入会出错。
     */
    public LWECiphertext switchModulus(long newModulus) {
        java.math.BigInteger bq = java.math.BigInteger.valueOf(modulus);
        java.math.BigInteger bn = java.math.BigInteger.valueOf(newModulus);
        java.math.BigInteger half = bq.shiftRight(1);
        long[] newA = new long[a.length];
        for (int i = 0; i < a.length; i++) {
            newA[i] = java.math.BigInteger.valueOf(a[i]).multiply(bn)
                    .add(half).divide(bq).mod(bn).longValueExact();
        }
        long newB = java.math.BigInteger.valueOf(b).multiply(bn)
                .add(half).divide(bq).mod(bn).longValueExact();
        return new LWECiphertext(newA, newB, newModulus, plaintextModulus);
    }

    /** 输出为十六进制短串,便于跨语言/跨实现逐比特对比 */
    public String toHexDigest() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("q=%d t=%d d=%d%n", modulus, plaintextModulus, a.length));
        sb.append("b=").append(Long.toHexString(b)).append(System.lineSeparator());
        for (int i = 0; i < a.length; i++) {
            sb.append(Long.toHexString(a[i]));
            sb.append(i + 1 < a.length ? "," : "");
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return "LWECiphertext{d=" + a.length + ", q=" + modulus
                + ", b=" + b + ", a[0..2]=" + Arrays.toString(Arrays.copyOf(a, Math.min(3, a.length))) + "}";
    }
}
