package cape.he;

import java.util.Arrays;

/**
 * LWE 密钥。
 *
 * 本实现用【三值密钥】s ∈ {0,1,2}^d,而不是常见的二进制密钥。
 *
 * 为什么要三值:
 *   Pirouette / CAPE 这类方案的盲旋转需要更细的控制粒度。
 *   二进制密钥下 CMUX 只需一次"二选一";三值密钥下需要两次
 *   (低位一次、高位一次),对应代码里的 ternary_mux。
 *
 *   注意:这条来自 Pirouette 的实现观察,你们的最终选择应以
 *   老师的 Java 实现为准 —— 如果老师用的是二进制密钥,
 *   把 generate 里的取值改成 {0,1} 即可,其余代码不用动。
 */
public final class LWESecretKey {

    private final long[] s;
    private final long modulus;

    public LWESecretKey(long[] s, long modulus) {
        this.s = s;
        this.modulus = modulus;
    }

    public long[] getS() {
        return s;
    }

    public long getModulus() {
        return modulus;
    }

    public int dimension() {
        return s.length;
    }

    @Override
    public String toString() {
        long ones = 0, twos = 0;
        for (long v : s) {
            if (v == 1) ones++;
            if (v == 2) twos++;
        }
        return "LWESecretKey{d=" + s.length + ", 汉明重量(1)=" + ones + ", 重量(2)=" + twos + "}";
    }

    /** 仅用于调试:不要在生产代码里打印密钥 */
    public String toHexDigest() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length; i++) {
            sb.append(Long.toHexString(s[i]));
            sb.append(i + 1 < s.length ? "," : "");
        }
        return sb.toString();
    }

    public LWESecretKey copy() {
        return new LWESecretKey(Arrays.copyOf(s, s.length), modulus);
    }
}
