package com.fusepir.rgsw;

import edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.seal.Decryptor;
import edu.alibaba.mpc4j.crypto.fhe.seal.Encryptor;
import edu.alibaba.mpc4j.crypto.fhe.seal.Evaluator;
import edu.alibaba.mpc4j.crypto.fhe.seal.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.seal.Plaintext;
import edu.alibaba.mpc4j.crypto.fhe.seal.SecretKey;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.seal.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.seal.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.seal.modulus.Modulus;

import java.math.BigInteger;
import java.util.Random;

/**
 * 建立在 <b>MPC4J 的 BFV</b> 之上的 RGSW 层。
 *
 * <p>与 `com.fusepir.rlwe`（自研 RLWE）的关系：**这是新的主路径，自研那套只作为校验工具保留**。
 * 理由：协议级运算（CtCtMul / 重线性化含缩放回落 / 槽位打包 / 旋转 / 序列化）MPC4J 都是现成且成熟的，
 * 自研那套要补齐这些需要几百行高难度代码（实测已经卡在"缩放回落"上）。
 *
 * <h3>RGSW 与外部乘积怎么架在 MPC4J 上</h3>
 * <ul>
 *   <li><b>原始加密</b>：MPC4J 没有"不缩放加密"，用
 *       "加密零 + 把消息加进系数"来实现。注意 SEAL 的密文默认在 <b>NTT 域</b>，
 *       而 NTT 是线性的，所以可以直接在 NTT 域加消息：
 *       <br>· 常数消息 g → 每个 NTT 系数都加 g（因为 NTT(常数 c) = 全 c）
 *       <br>· 消息 g·s → 加 g·(密钥的 NTT 系数)，而 SEAL 的私钥本来就是 NTT 存储的</li>
 *   <li><b>切段</b>：把源密文拷一份、转回系数域，逐系数跨素数还原成大整数，再按 B 进制切段；</li>
 *   <li><b>外部乘积</b>：每层用 {@code Evaluator.multiplyPlain}（乘的是公开的数字多项式）
 *       与 RGSW 分量相乘并累加。数字小于 B，而 B = 2^16 = 65536 &lt; t = 65537，正好落在 Z_t 里。</li>
 * </ul>
 */
public final class Mpc4jRgsw {

    /** 多项式次数 */
    public final int n;
    /** 明文模数 t */
    public final long t;
    /** gadget 基数 B */
    public final int base;
    /** gadget 层数 */
    public final int levels;

    public final EncryptionParameters parms;
    public final SealContext context;
    public final KeyGenerator keyGen;
    public final SecretKey sk;
    public final Encryptor encryptor;
    public final Decryptor decryptor;
    public final Evaluator evaluator;

    /** 系数模数的各素数 */
    public final Modulus[] primes;
    /** 系数模数 q = 各素数之积 */
    public final BigInteger q;
    /** q 的位宽 */
    public final int qBits;
    /** 增量式 CRT 每一步的逆元 */
    private final BigInteger[] crtStepInv;

    /** @param unused 保留参数（素数个数由 bfvDefault 自动决定） */
    public Mpc4jRgsw(int n, long t, int unused, int base) {
        this.n = n;
        this.t = t;
        this.base = base;

        this.parms = new EncryptionParameters(SchemeType.BFV);
        parms.setPolyModulusDegree(n);
        parms.setCoeffModulus(CoeffModulus.bfvDefault(n)); // 自带符合 128-bit 安全标准的参数
        parms.setPlainModulus(new Modulus(t));
        this.context = new SealContext(parms);
        if (!context.isParametersSet()) {
            throw new IllegalStateException("SEAL 参数无效: " + context.parametersErrorMessage());
        }
        this.primes = parms.coeffModulus();
        BigInteger prod = BigInteger.ONE;
        for (Modulus m : primes) {
            prod = prod.multiply(BigInteger.valueOf(m.value()));
        }
        this.q = prod;
        this.qBits = q.bitLength();

        BigInteger running = BigInteger.ONE;
        this.crtStepInv = new BigInteger[primes.length];
        for (int k = 0; k < primes.length; k++) {
            if (k == 0) {
                running = BigInteger.valueOf(primes[0].value());
                continue;
            }
            BigInteger mk = BigInteger.valueOf(primes[k].value());
            crtStepInv[k] = running.mod(mk).modInverse(mk);
            running = running.multiply(mk);
        }

        this.levels = levelsFor(base, q);
        this.keyGen = new KeyGenerator(context);
        this.sk = keyGen.secretKey();
        this.encryptor = new Encryptor(context, sk);
        this.decryptor = new Decryptor(context, sk);
        this.evaluator = new Evaluator(context);
    }

    private static int levelsFor(int base, BigInteger q) {
        int l = 1;
        BigInteger cap = BigInteger.valueOf(base);
        while (cap.compareTo(q) <= 0) {
            cap = cap.multiply(BigInteger.valueOf(base));
            l++;
        }
        return l;
    }

    // ---------------- 基本 RLWE 运算（全部走 MPC4J） ----------------

    /** 普通 BFV 加密：消息 ∈ Z_t */
    public Ciphertext encrypt(long[] m) {
        Plaintext pt = new Plaintext(m);
        Ciphertext ct = new Ciphertext();
        encryptor.encryptSymmetric(pt, ct);
        return ct;
    }

    /**
     * 解密：MPC4J 内部已完成缩放与取整，直接得到 Z_t 上的消息。
     *
     * <p>注意 BFV 解密要求密文处于<b>系数域</b>，所以 NTT 域的密文要先转回来
     * （拷一份转，不改调用方的密文）。
     */
    public long[] decrypt(Ciphertext ct) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        if (copy.isNttForm()) {
            evaluator.transformFromNttInplace(copy);
        }
        Plaintext pt = new Plaintext(n);
        decryptor.decrypt(copy, pt);
        long[] out = new long[n];
        for (int i = 0; i < n; i++) {
            out[i] = pt.get(i);
        }
        return out;
    }

    public void addInplace(Ciphertext acc, Ciphertext x) {
        evaluator.addInplace(acc, x);
    }

    public void subInplace(Ciphertext acc, Ciphertext x) {
        evaluator.subInplace(acc, x);
    }

    public Ciphertext add(Ciphertext x, Ciphertext y) {
        Ciphertext out = new Ciphertext();
        evaluator.add(x, y, out);
        return out;
    }

    /** 加密零 */
    public Ciphertext encryptZero() {
        Ciphertext ct = new Ciphertext();
        encryptor.encryptZeroSymmetric(ct);
        return ct;
    }

    /** 确保密文处于 NTT 域（MPC4J 的密文形式跟着明文走，所以要显式统一） */
    private Ciphertext toNtt(Ciphertext ct) {
        if (!ct.isNttForm()) {
            evaluator.transformToNttInplace(ct);
        }
        return ct;
    }

    // ---------------- 原始加密（不缩放）+ RGSW ----------------

    /**
     * 在 NTT 域把一个"常数消息 g"加到密文的分量 polyIndex 上。
     * NTT(常数 c) = 全 c，所以每个 NTT 系数都加 g。
     */
    private void addConstantNtt(Ciphertext ct, int polyIndex, BigInteger g) {
        long[] data = ct.data();
        int L = primes.length;
        for (int j = 0; j < L; j++) {
            long p = primes[j].value();
            long v = g.mod(BigInteger.valueOf(p)).longValue();
            int off = (polyIndex * L + j) * n;
            for (int i = 0; i < n; i++) {
                long s = data[off + i] + v;
                data[off + i] = s >= p ? s - p : s;
            }
        }
    }

    /**
     * 在 NTT 域把 g·(私钥) 加到分量 polyIndex 上。
     * SEAL 的私钥本身以 NTT 形式存储，所以直接逐系数相乘相加即可。
     */
    private void addScaledSecretNtt(Ciphertext ct, int polyIndex, BigInteger g) {
        long[] data = ct.data();
        long[] skData = sk.data().data();
        int L = primes.length;
        for (int j = 0; j < L; j++) {
            long p = primes[j].value();
            long v = g.mod(BigInteger.valueOf(p)).longValue();
            int off = (polyIndex * L + j) * n;
            int skOff = j * n;
            for (int i = 0; i < n; i++) {
                long prod = skData[skOff + i] * v % p;
                long s = data[off + i] + prod;
                data[off + i] = s >= p ? s - p : s;
            }
        }
    }

    /** 一个 RGSW 密文：两组、每组 levels 个密文 */
    public static final class Rgsw {
        public final Ciphertext[] group0;
        public final Ciphertext[] group1;

        Rgsw(Ciphertext[] g0, Ciphertext[] g1) {
            this.group0 = g0;
            this.group1 = g1;
        }

        public int size() {
            return group0.length + group1.length;
        }
    }

    /**
     * RGSW 加密一个<b>常数</b>选择器 μ ∈ {0,1}。
     *
     * <p>group0[i] 的相位 = g_i·μ；group1[i] 的相位 = g_i·(μ·s)。
     */
    public Rgsw encryptRgswConstant(long mu) {
        if (mu != 0 && mu != 1) {
            throw new IllegalArgumentException("本实现目前只支持常数选择器 0/1");
        }
        Ciphertext[] g0 = new Ciphertext[levels];
        Ciphertext[] g1 = new Ciphertext[levels];
        BigInteger power = BigInteger.ONE;
        BigInteger b = BigInteger.valueOf(base);
        for (int i = 0; i < levels; i++) {
            Ciphertext c0 = toNtt(encryptZero());
            if (mu == 1) {
                addConstantNtt(c0, 0, power);          // g_i · μ
            }
            g0[i] = c0;

            Ciphertext c1 = toNtt(encryptZero());
            if (mu == 1) {
                addScaledSecretNtt(c1, 0, power);      // g_i · (μ·s)
            }
            g1[i] = c1;

            power = power.multiply(b);
        }
        return new Rgsw(g0, g1);
    }

    // ---------------- 切段与外部乘积 ----------------

    /** 把源密文某个分量（系数域）的第 i 个系数还原成 Z_q 上的大整数 */
    private BigInteger crtAt(long[] data, int polyIndex, int coeffIndex) {
        int L = primes.length;
        BigInteger x = null;
        BigInteger mv = null;
        for (int j = 0; j < L; j++) {
            long pj = primes[j].value();
            long rj = data[(polyIndex * L + j) * n + coeffIndex];
            if (j == 0) {
                x = BigInteger.valueOf(rj);
                mv = BigInteger.valueOf(pj);
                continue;
            }
            BigInteger mj = BigInteger.valueOf(pj);
            BigInteger diff = BigInteger.valueOf(rj).subtract(x).mod(mj);
            BigInteger tv = diff.multiply(crtStepInv[j]).mod(mj);
            x = x.add(mv.multiply(tv));
            mv = mv.multiply(mj);
        }
        return x;
    }

    /** 把一个分量切成 levels 段（输入会先转回系数域，用副本，不动原密文） */
    public long[][] decompose(Ciphertext ct, int polyIndex) {
        Ciphertext copy = new Ciphertext();
        copy.copyFrom(ct);
        // MPC4J 的密文形式跟着明文走：先统一到"系数域"再读系数
        if (copy.isNttForm()) {
            evaluator.transformFromNttInplace(copy);
        }
        long[] data = copy.data();
        long[][] digits = new long[levels][n];
        BigInteger b = BigInteger.valueOf(base);
        for (int i = 0; i < n; i++) {
            BigInteger x = crtAt(data, polyIndex, i);
            for (int k = 0; k < levels; k++) {
                digits[k][i] = x.mod(b).longValueExact();
                x = x.divide(b);
            }
        }
        return digits;
    }

    /**
     * 外部乘积：RGSW ⊗ RLWE → RLWE。
     *
     * <p>切段数字 &lt; B = 2^16 = 65536 &lt; t = 65537，正好能作为 Z_t 明文喂给
     * {@code multiplyPlain}。
     */
    public Ciphertext externalProduct(Rgsw rgsw, Ciphertext src) {
        long[][] d0 = decompose(src, 0);
        long[][] d1 = decompose(src, 1);

        // 累加器必须与 RGSW 分量同形式（NTT 域）
        Ciphertext acc = toNtt(encryptZero());
        Ciphertext tmp = new Ciphertext();
        for (int i = 0; i < levels; i++) {
            multiplyPlainNtt(rgsw.group0[i], d0[i], tmp);
            evaluator.addInplace(acc, tmp);
            multiplyPlainNtt(rgsw.group1[i], d1[i], tmp);
            evaluator.addInplace(acc, tmp);
        }
        return acc;
    }

    /**
     * 密文乘"公开数字多项式"。
     *
     * <p>MPC4J 要求明文与密文<b>同形式</b>，所以先把数字明文转到 NTT 域
     * （用该密文的 parmsId），再调 multiplyPlain。
     */
    private void multiplyPlainNtt(Ciphertext ct, long[] digits, Ciphertext dst) {
        Plaintext pt = new Plaintext(digits);
        evaluator.transformToNttInplace(pt, ct.parmsId());
        evaluator.multiplyPlain(ct, pt, dst);
    }

    /** CMUX：c=0 得 a，c=1 得 b */
    public Ciphertext cmux(Rgsw rgsw, Ciphertext a, Ciphertext b) {
        Ciphertext diff = new Ciphertext();
        evaluator.sub(b, a, diff);
        Ciphertext prod = externalProduct(rgsw, diff);
        return add(a, prod);
    }

    public String describe() {
        return String.format(
            "N=%d, t=%d, primes=%d, q=%d bit, base=%d, levels=%d",
            n, t, primes.length, qBits, base, levels);
    }

    // ---------------- 自检 ----------------

    public static void main(String[] args) {
        System.out.println("=== RGSW on top of MPC4J (BFV) ===");
        // MPC4J 的 Galois 工具在每层模数上分配 N^2 个整数，素数多了会 OOM；
        // 实测 N=1024 + 2 素数很轻松，够验证逻辑。
        // N=2048 + bfvDefault：模数约 54 位，噪声预算足够容纳外部乘积
        // （N=1024 只能装约 27 位，噪声会超预算；这是 SEAL 的 128-bit 安全下限决定的）
        Mpc4jRgsw m = new Mpc4jRgsw(2048, 65537L, 0, 1 << 16);
        System.out.println("[params] " + m.describe());
        System.out.println();

        Random rnd = new Random(20260916L);
        int failed = 0;

        // 1. RLWE 往返
        long[] msg = new long[m.n];
        for (int i = 0; i < m.n; i++) {
            msg[i] = rnd.nextInt(64);
        }
        Ciphertext ct = m.encrypt(msg);
        long[] back = m.decrypt(ct);
        long diff = countDiff(msg, back);
        failed += report("Test 1  MPC4J RLWE round-trip", diff == 0,
            "wrong coefficients = " + diff);

        // 2. RGSW(1) ⊗ ct 应当等于 ct
        Mpc4jRgsw.Rgsw one = m.encryptRgswConstant(1);
        Ciphertext prod1 = m.externalProduct(one, ct);
        long[] out1 = m.decrypt(prod1);
        long diff1 = countDiff(msg, out1);
        failed += report("Test 2  RGSW(1) x ct  = ct", diff1 == 0,
            "wrong coefficients = " + diff1);

        // 3. RGSW(0) ⊗ ct 应当是 0
        Mpc4jRgsw.Rgsw zero = m.encryptRgswConstant(0);
        Ciphertext prod0 = m.externalProduct(zero, ct);
        long[] out0 = m.decrypt(prod0);
        long bad0 = 0;
        for (long v : out0) {
            if (v != 0) {
                bad0++;
            }
        }
        failed += report("Test 3  RGSW(0) x ct  = 0", bad0 == 0,
            "non-zero coefficients = " + bad0);

        // 4. CMUX：A + RGSW(mu)(B-A)
        long[] mA = new long[m.n];
        long[] mB = new long[m.n];
        for (int i = 0; i < m.n; i++) {
            mA[i] = 11;
            mB[i] = 22;
        }
        Ciphertext a = m.encrypt(mA);
        Ciphertext b = m.encrypt(mB);
        for (int mu = 0; mu <= 1; mu++) {
            Ciphertext res = m.cmux(m.encryptRgswConstant(mu), a, b);
            long[] got = m.decrypt(res);
            long[] want = mu == 0 ? mA : mB;
            long d = countDiff(want, got);
            failed += report("Test 4." + mu + "  CMUX(mu=" + mu + ") -> "
                + (mu == 0 ? "A" : "B"), d == 0, "wrong coefficients = " + d);
        }

        System.out.println();
        System.out.println(failed == 0 ? "=== ALL TESTS PASSED ===" : "=== " + failed + " FAILED ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static long countDiff(long[] a, long[] b) {
        long c = 0;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                c++;
            }
        }
        return c;
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
