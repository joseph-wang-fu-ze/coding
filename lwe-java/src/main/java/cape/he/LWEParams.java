package cape.he;

/**
 * LWE 参数配置。
 *
 * ============================ 参数来源 ============================
 * 取自 Pirouette 论文(PoPETs 2026)*Table 4* —— 即
 * https://github.com/KULeuven-COSIC/Pirouette 的实现参数。
 *
 *   Parameter   n     N       log2(q)  log2(Q)  B     B_rgsw  l_rgsw  sigma^2
 *   Value       512   2^11    12       56       2^8   2^4     8       3.192
 *
 * 论文 §1.1(第 122 行)另述:
 *   "Our implementation uses a 25-bit plaintext modulus and 32-bit ciphertext
 *    modulus for LWE."
 *
 * 两者不矛盾,说的是不同阶段:
 *   - 客户端**查询**用的 LWE:32-bit 模数、25-bit 明文
 *     (对应 Table 3 的 log2(q_in) = 32)
 *   - 盲旋转 / 方案切换后进入计算的 LWE:log2(q) = 12,即 q = 2^12(Table 4)
 *
 * 本类采用**后者**(q = 2^12),因为盲旋转要求 q 为 2 的幂。
 * ==================================================================
 *
 * 【关键结构约束】q = 2N
 *   论文 §3.2(第 435 行)明确:"we consider input LWE ciphertexts with
 *   modulus q = 2N"。
 *
 *   用 Table 4 验证:N = 2^11 = 2048,故 2N = 2^12 = 4096 = q ✓
 *
 *   含义:q 与 N **不独立** —— 改 N 必须同步改 q。
 *   Algorithm 1/2 的输入签名 LWEs(m, N/2^(nu-1)) 与 LWEs(m, q/2^(d*nu))
 *   都建立在这个关系之上。
 */
public final class LWEParams {

    // ==================== 默认值:Pirouette Table 4 ====================

    /** LWE 密钥维度 n。Pirouette Table 4:n = 512 */
    public static final int DEFAULT_DIMENSION = 512;

    /**
     * LWE 密文模数 q = 2^12 = 4096。Pirouette Table 4:log2(q) = 12。
     * 结构约束:必须满足 q = 2N,其中 N = 2^11 = 2048 是环维度。
     */
    public static final long DEFAULT_MODULUS = 1L << 12;

    /**
     * 明文模数 t。
     *
     * 注意:Pirouette **没有直接给出这一项**。论文只说了查询阶段的 25-bit 明文模数,
     * 而进入盲旋转后 log2(q) 只剩 12 bit,装不下 25 bit 的明文。
     *
     * 这里取 t = 16(4 bit)是**带依据的推断值**:
     *   Delta = q/t = 4096/16 = 256
     *   噪声预算 = Delta/2 = 128
     *   sigma = sqrt(3.192) ≈ 1.787
     *   余量比 = sigma/预算 ≈ 0.014,很宽裕
     *   (实测 decryption 失败率 0/2000,见 LWESelfTest)
     *
     * 实际取值仍需与老师的实现 / CAPE 论文对齐。
     */
    public static final int DEFAULT_PLAINTEXT_MODULUS = 16;

    /**
     * 噪声标准差 sigma = sqrt(3.192) ≈ 1.7866。
     * Pirouette Table 4 给的是**方差** sigma^2 = 3.192。
     */
    public static final double DEFAULT_SIGMA = 1.7866;

    // ==================== 字段 ====================

    /** 密钥维度 d */
    public final int dimension;

    /** 密文模数 q,必须是 2 的幂 */
    public final long modulus;

    /** 明文模数 t */
    public final int plaintextModulus;

    /** 噪声标准差 */
    public final double sigma;

    /** 缩放因子 Delta = floor(q / t),把明文放大到密文空间 */
    public final long delta;

    public LWEParams(int dimension, long modulus, int plaintextModulus, double sigma) {
        if (dimension <= 0) {
            throw new IllegalArgumentException("dimension 必须为正数, 当前 = " + dimension);
        }
        if (modulus < 2) {
            throw new IllegalArgumentException("modulus 必须 >= 2, 当前 = " + modulus);
        }
        if ((modulus & (modulus - 1)) != 0) {
            throw new IllegalArgumentException(
                    "modulus 必须是 2 的幂(盲旋转的硬性要求), 当前 = " + modulus
                            + "。若换成非 2 的幂,Rotate 索引映射会失效。");
        }
        if (plaintextModulus < 2) {
            throw new IllegalArgumentException("plaintextModulus 必须 >= 2, 当前 = " + plaintextModulus);
        }
        if (plaintextModulus > modulus) {
            throw new IllegalArgumentException("plaintextModulus 不能超过 modulus");
        }
        if (sigma < 0) {
            throw new IllegalArgumentException("sigma 不能为负数");
        }

        this.dimension = dimension;
        this.modulus = modulus;
        this.plaintextModulus = plaintextModulus;
        this.sigma = sigma;
        this.delta = modulus / plaintextModulus;

        if (this.delta == 0) {
            throw new IllegalArgumentException("q / t == 0, 噪声余量不足, 请缩小 t 或增大 q");
        }
    }

    /**
     * 按 RLWE 环维度 N 生成 <b>CAPE 对齐</b> 的参数: q = 2N。
     *
     * 为什么 q = 2N: 盲旋转要把 b 编码成 X^(-b) 写进长度 2N 的累加器,
     * 索引按 mod 2N 取; 只有 q = 2N 时"模 q 的加法群"才能同构嵌入"模 2N 的旋转群"。
     * CAPE 的环维度是 N = 16384, 所以盲旋转输入的 q 必须是 2^15 = 32768。
     *
     * 注意 t 不是自由参数: t = 2^nu, nu 是"每次盲旋转能处理的位数",
     * 索引位数 k 需要 ceil(k/nu) 次盲旋转。详见 coding/ 下的汇总说明。
     *
     * @param ringDimension         RLWE 环维度 N
     * @param dimension             LWE 维度 d (CAPE 未给出, Pirouette 取 512)
     * @param perRotationPrecision  nu, 每次盲旋转处理的位数; t = 2^nu
     * @param sigma                 噪声标准差
     */
    public static LWEParams forRingDimension(int ringDimension, int dimension,
                                             int perRotationPrecision, double sigma) {
        return new LWEParams(dimension, 2L * ringDimension,
                1 << perRotationPrecision, sigma);
    }

    /** 使用 Pirouette Table 4 的默认参数构造 */
    public static LWEParams withDefaults() {
        return new LWEParams(DEFAULT_DIMENSION, DEFAULT_MODULUS,
                DEFAULT_PLAINTEXT_MODULUS, DEFAULT_SIGMA);
    }

    /**
     * 精确模式:噪声设为 0。
     *
     * 用途(老师建议的调试策略):先把方案本身跑通,排除噪声因素。
     * 噪声为 0 时解密在数学上精确,任何错误都必然来自**逻辑 bug**
     * (下标错、域搞混、模数切换错),而不是噪声预算不足。
     *
     * ⚠️ 注意:sigma = 0 **只用于验证逻辑,不代表任何安全性**。
     *    真实评测必须回到 withDefaults() 的噪声值。
     *    另外,盲旋转层自身会引入噪声,那部分不受此参数控制。
     */
    public static LWEParams exactlyNoiseless() {
        return new LWEParams(DEFAULT_DIMENSION, DEFAULT_MODULUS,
                DEFAULT_PLAINTEXT_MODULUS, 0.0);
    }

    /**
     * 结构约束校验:盲旋转要求 q = 2N。
     *
     * 本类的 modulus 即 q。环维度 N 由 RLWE 层决定(须与杨楼的实现一致)。
     * 若两者不等,盲旋转的下标映射会失效。
     *
     * @param ringDimension N,必须是 2 的幂
     */
    public boolean satisfiesBlindRotateConstraint(long ringDimension) {
        return modulus == 2 * ringDimension;
    }

    /**
     * 噪声容限:解密时允许的误差上界(约为 Delta/2)。
     * 用于自检:如果 sigma 太大,解密会开始出错。
     */
    public long errorTolerance() {
        return delta / 2;
    }

    /** 模数 q 的位宽 */
    public int modulusBits() {
        return Long.numberOfTrailingZeros(modulus); // q 是 2 的幂,故等于 log2(q)
    }

    /**
     * 参数自检:判断噪声是否在可解范围内。
     *
     * 重要:相位噪声 = e 本身,【不随维度 d 放大】。
     *   因为 phase = b - <a,s> = (<a,s> + Delta*m + e) - <a,s> = Delta*m + e,
     *   构造 b 和解密用的是同一个 a,<a,s> 项精确抵消。
     *
     * 因此判据只看 e 的大小与预算 Delta/2 的关系。
     * 采样器按 6*sigma 截断,故用 6*sigma 作为最坏情形估计。
     *
     * (注:若在别的方案里 a 本身带误差,或秘密被复用出偏差,
     * 才会出现 sigma*sqrt(d) 那类放大 —— 本方案不适用。)
     */
    public boolean isSane() {
        double worstCaseNoise = 6.0 * sigma;
        return worstCaseNoise < errorTolerance();
    }

    /** 噪声预算占用率:最坏噪声 / 预算。> 1 则必然出错 */
    public double noiseBudgetRatio() {
        return errorTolerance() == 0 ? Double.POSITIVE_INFINITY
                : (6.0 * sigma) / errorTolerance();
    }

    @Override
    public String toString() {
        return String.format("LWEParams{d=%d, q=2^%d, t=%d, sigma=%.2f, Delta=%d, budget=%d, usage=%.3f}",
                dimension, modulusBits(), plaintextModulus, sigma, delta, errorTolerance(), noiseBudgetRatio());
    }
}
