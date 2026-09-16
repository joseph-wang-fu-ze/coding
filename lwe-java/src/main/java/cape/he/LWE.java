package cape.he;

import java.security.SecureRandom;
import java.util.Random;

/**
 * LWE 加解密。
 *
 * 这是整个 HE 部分的地基 —— 也是团队的"体温计":
 * 后面 BlindRotate / SampleExtract 写完之后,都靠它来验证正确性。
 *
 * 支持的运算:
 *   keyGen()           生成三值密钥
 *   encrypt(m)         公钥式加密(此处用私钥直接生成,教学/测试用)
 *   decrypt(ct)        解密,失败时返回 -1
 *   decryptSafe(ct)    解密,失败时抛异常(测试用,更容易暴露问题)
 *   encode/decode      明文 <-> 缩放后的环元素
 *
 * 使用示例:
 *   LWEParams p = LWEParams.withDefaults();
 *   LWE lwe = new LWE(p);
 *   LWESecretKey sk = lwe.keyGen();
 *   LWECiphertext ct = lwe.encrypt(sk, 42);
 *   assert lwe.decrypt(sk, ct) == 42;
 */
public final class LWE {

    /** 正态分布采样时的截断倍数:超过 TAIL_CUTOFF * sigma 的样本重采 */
    private static final int TAIL_CUTOFF = 6;

    private final LWEParams params;
    private final Random random;

    public LWE(LWEParams params) {
        this(params, new SecureRandom());
    }

    /** 允许注入固定种子的 Random,便于生成可复现的测试向量 */
    public LWE(LWEParams params, Random random) {
        this.params = params;
        this.random = random;
    }

    public LWEParams params() {
        return params;
    }

    // ==================== 密钥生成 ====================

    /**
     * 生成三值密钥 s ∈ {0,1,2}^d。
     * 若你的方案需要二进制密钥,把 nextSecretCoefficient 改成只返回 0/1。
     */
    public LWESecretKey keyGen() {
        long[] s = new long[params.dimension];
        for (int i = 0; i < s.length; i++) {
            s[i] = nextSecretCoefficient();
        }
        return new LWESecretKey(s, params.modulus);
    }

    /** 三值:以较小概率取 0,其余取 1 或 2(近似均匀三值分布) */
    private long nextSecretCoefficient() {
        // 10% 取 0,其余在 {1,2} 里均分 —— 稀疏密钥,更贴近实际方案
        int r = random.nextInt(10);
        if (r == 0) {
            return 0;
        }
        return random.nextBoolean() ? 1 : 2;
    }

    // ==================== 明文编码 ====================

    /**
     * 把明文 m ∈ [0, t) 编码成 Z_q 中的元素:Delta * m mod q。
     */
    public long encode(long message) {
        if (message < 0 || message >= params.plaintextModulus) {
            throw new IllegalArgumentException(
                    "明文必须在 [0, " + params.plaintextModulus + ") 内, 当前 = " + message);
        }
        return (params.delta * message) % params.modulus;
    }

    /**
     * 从相位 phase ∈ Z_q 解出明文。
     * 步骤:中心化 -> 除以 Delta 并四舍五入 -> 归一化到 [0, t)。
     */
    public long decode(long phase) {
        long centered = ModMath.center(phase, params.modulus);
        long message = Math.round((double) centered / params.delta);
        long t = params.plaintextModulus;
        return ((message % t) + t) % t;
    }

    // ==================== 加解密 ====================

    /**
     * 加密:ct = (a, <a,s> + Delta*m + e mod q)
     */
    public LWECiphertext encrypt(LWESecretKey sk, long message) {
        long q = params.modulus;
        int d = params.dimension;

        long[] a = new long[d];
        for (int i = 0; i < d; i++) {
            a[i] = nextUniform(q);
        }

        long dot = ModMath.dotProduct(a, sk.getS(), q);
        long e = sampleError();
        long b = ModMath.add(ModMath.add(dot, encode(message), q), e, q);

        return new LWECiphertext(a, b, q, params.plaintextModulus);
    }

    /**
     * 解密。若噪声超出容限,结果可能不为 -1 但已经错了 ——
     * 判断正确性请用 decryptSafe 或逐次统计。
     */
    public long decrypt(LWESecretKey sk, LWECiphertext ct) {
        long phase = phase(sk, ct);
        return decode(phase);
    }

    /**
     * 解密并校验:结果超出明文范围时抛异常。
     * 测试时推荐用这个 —— 它能立刻暴露噪声溢出问题。
     */
    public long decryptSafe(LWESecretKey sk, LWECiphertext ct) {
        long phase = phase(sk, ct);
        long centered = ModMath.center(phase, params.modulus);
        double raw = (double) centered / params.delta;
        long rounded = Math.round(raw);

        // 若距离最近的 Delta 倍数太远,说明噪声已经吃掉了明文
        double deviation = Math.abs(raw - rounded);
        if (deviation > 0.25) {
            throw new IllegalStateException(
                    String.format("解密失败: 噪声超限(偏离 %.3f 个 Delta 单位)。"
                                    + "phase 中心化=%d, Delta=%d。"
                                    + "请检查 sigma=%s 与维度 d=%d 是否匹配。",
                            deviation, centered, params.delta, params.sigma, params.dimension));
        }
        long t = params.plaintextModulus;
        return ((rounded % t) + t) % t;
    }

    /**
     * 计算相位 phase = b - <a, s> mod q。
     *
     * 这个方法是【暴露给上层用的】:
     * 盲旋转结束后,SampleExtract 输出的就是 (A, B) 形式的 LWE,
     * 你需要同样的方式算它的 phase 来验证。
     */
    public long phase(LWESecretKey sk, LWECiphertext ct) {
        return phase(sk, ct.getA(), ct.getB());
    }

    /** 相位计算的重载版本,供 SampleExtract 的输出直接使用 */
    public long phase(LWESecretKey sk, long[] a, long b) {
        long q = params.modulus;
        if (a.length != sk.dimension()) {
            throw new IllegalArgumentException(
                    "维度不匹配: LWE 向量 d=" + a.length + ", 密钥 d=" + sk.dimension());
        }
        long dot = ModMath.dotProduct(a, sk.getS(), q);
        return ModMath.sub(b, dot, q);
    }

    // ==================== 采样 ====================

    /** 均匀采样 Z_q —— a 的每个分量 */
    public long nextUniform(long q) {
        // q 是 2 的幂时,直接用位掩码,无偏且快
        if ((q & (q - 1)) == 0) {
            return random.nextLong() & (q - 1);
        }
        long r;
        do {
            r = random.nextLong() & Long.MAX_VALUE;
        } while (r >= q);
        return r;
    }

    /**
     * 离散高斯噪声采样,返回 Z_q 中的元素(已归一化到 [0, q))。
     * 用截断正态分布近似(超过 TAIL_CUTOFF * sigma 的重采)。
     */
    public long sampleError() {
        long e = sampleCenteredGaussian();
        long q = params.modulus;
        return ((e % q) + q) % q;
    }

    /** 返回中心化的噪声样本,可能为负 —— 便于统计噪声大小 */
    public long sampleCenteredGaussian() {
        double sigma = params.sigma;
        if (sigma == 0) {
            return 0;
        }
        long bound = (long) Math.ceil(TAIL_CUTOFF * sigma);
        while (true) {
            long candidate = Math.round(random.nextGaussian() * sigma);
            if (Math.abs(candidate) <= bound) {
                return candidate;
            }
        }
    }

    // ==================== 二值密钥(盲旋转需要) ====================

    /**
     * 生成二值密钥 s in {0,1}^d。
     *
     * CMUX 是"按位二选一",所以盲旋转要求密钥必须是二值的:
     * 每一位对应一个 RGSW 密文(自举密钥),服务器按位选择"旋转 / 不旋转"。
     * 若密钥取 {0,1,2},就需要三路选择,自举密钥结构也得跟着改。
     */
    public LWESecretKey keyGenBinary() {
        long[] s = new long[params.dimension];
        for (int i = 0; i < s.length; i++) {
            s[i] = random.nextBoolean() ? 1 : 0;
        }
        return new LWESecretKey(s, params.modulus);
    }

    /** 把二值密钥导出成 int[],直接喂给 RGSW 层的自举密钥生成 */
    public static int[] toBitArray(LWESecretKey sk) {
        long[] s = sk.getS();
        int[] bits = new int[s.length];
        for (int i = 0; i < s.length; i++) {
            if (s[i] != 0 && s[i] != 1) {
                throw new IllegalStateException("密钥第 " + i + " 位不是 0/1,无法用于盲旋转");
            }
            bits[i] = (int) s[i];
        }
        return bits;
    }

    // ==================== 模数切换(连接 RLWE 层的桥梁) ====================

    /**
     * 解密"模数已被切换过"的密文。
     *
     * 切换后比例因子变了(Delta = q' / t),所以不能用 params.delta 解码,
     * 必须按密文自己的模数重算比例。
     */
    public long decryptSwitched(LWESecretKey sk, LWECiphertext ct) {
        long q = ct.getModulus();
        long delta = q / ct.getPlaintextModulus();
        long dot = ModMath.dotProduct(ct.getA(), sk.getS(), q);
        long phase = ModMath.sub(ct.getB(), dot, q);
        long centered = ModMath.center(phase, q);
        long m = Math.round((double) centered / delta);
        long t = ct.getPlaintextModulus();
        return ((m % t) + t) % t;
    }

    /**
     * 模数切换引入的噪声上界(相位单位)。
     *
     * 依次对 a 的每个分量做舍入,每个分量的舍入误差 <= 1/2,
     * 与密钥做内积后误差 <= ||s||_1 / 2 = d/2(二值密钥)。
     * 也就是说切换本身就会带来 d/2 的噪声 -- 这是选 d 和 t 时的硬约束。
     */
    public static double switchNoiseBound(int dimension) {
        return dimension / 2.0;
    }
}
