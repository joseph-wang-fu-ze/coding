package edu.alibaba.mpc4j.s2pc.pir.stdpir.index.seal;

import java.util.List;

/**
 * Native 声明副本：包名、类名、方法名与 MPC4J 原版
 * {@code mpc4j-s2pc-pir/.../stdpir/index/seal/SealStdIdxPirNativeUtils.java} 完全一致。
 *
 * <p>为什么要这份副本：JNI 是按 {@code Java_<包>_<类>_<方法>} 的名字绑定符号的，
 * 所以只要包名类名方法签名一致，就能直接复用手写好的 C++ 实现
 * （{@code mpc4j-native-fhe/pir/std/...SealStdIdxPirNativeUtils.cpp}），
 * 而不必把整个 MPC4J Java 依赖树（网络层、RPC、协议框架…）拖进来。
 *
 * <p>原版方法是包级私有，这里放开成 {@code public} 以便本模块的测试调用；
 * 可见性不参与 JNI 符号解析，因此不影响绑定。
 *
 * <p>底层是 <b>真正的 Microsoft SEAL 4.0.0（C++）</b>，通过
 * {@code mpc4j-native-fhe.dll} 链接，不是纯 Java 移植版。
 */
public class SealStdIdxPirNativeUtils {

    static {
        System.loadLibrary("mpc4j-native-fhe");
    }

    private SealStdIdxPirNativeUtils() {
        // empty
    }

    /** BFV 参数（内部为 CoeffModulus::BFVDefault(polyModulusDegree, tc128)）。 */
    public static native byte[] generateEncryptionParams(int polyModulusDegree, long plainModulus);

    /** 返回 [publicKey, secretKey, galoisKeys]。 */
    public static native List<byte[]> keyGen(byte[] encryptionParams);

    /** 把系数域明文批量转成 NTT 域明文（数据库预处理）。 */
    public static native List<byte[]> nttTransform(byte[] encryptionParams, List<long[]> plaintextList);

    /** 生成 SealPIR 查询（单点选择向量的密文）。indices 与 nvec 长度必须相同。 */
    public static native List<byte[]> generateQuery(byte[] encryptionParams, byte[] publicKey, byte[] secretKey,
                                                   int[] indices, int[] nvec);

    /** 服务端生成应答（内部用 Galois 密钥做 expand_query 扩展 + 密文×明文累加）。 */
    public static native List<byte[]> generateReply(byte[] encryptionParams, byte[] galoisKey, List<byte[]> queryList,
                                                    byte[][] database, int[] nvec);

    /** 解密应答，得到系数域明文。 */
    public static native long[] decryptReply(byte[] encryptionParams, byte[] secretKey, List<byte[]> response,
                                             int dimension);

    /** 密文相对"能装下的最大明文"的体积膨胀比。 */
    public static native int expansionRatio(byte[] encryptionParams);
}
