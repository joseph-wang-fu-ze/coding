package edu.alibaba.mpc4j.work.psipir;

import java.util.List;

/**
 * Native 声明副本：与 MPC4J 原版
 * {@code mpc4j-work-psipir/.../Lpzl24BatchPirNativeUtils.java} 包名、类名、方法签名一致。
 *
 * <p>配套 C++ 实现在 {@code mpc4j-native-fhe/pir/...Lpzl24BatchPirNativeUtils.cpp}，
 * 由 {@code coding/native-jni/lib/mpc4j-native-fhe.dll} 提供（其中已静态链接真 SEAL 4.0.0）。
 *
 * <p>这一类是 CAPE 最相关的封装：它直接暴露了
 * <ul>
 *   <li>{@link #computeEncryptedPowers} —— <b>密文×密文 + 重线性化</b>（密文取幂）；</li>
 *   <li>{@link #optComputeMatches} —— <b>加密匹配</b>（Paterson-Stockmeyer 多项式求值），
 *       对应 CAPE 关键字匹配的打分环节；</li>
 *   <li>{@link #genEncryptionParameters} —— 可以<b>自定义系数模数位数</b>，
 *       不局限于 {@code BFVDefault}，便于对齐论文参数；</li>
 *   <li>{@link #processDatabase} —— 数据库明文的 PS 分解预处理。</li>
 * </ul>
 */
public class Lpzl24BatchPirNativeUtils {

    static {
        System.loadLibrary("mpc4j-native-fhe");
    }

    private Lpzl24BatchPirNativeUtils() {
        // empty
    }

    /** 生成 BFV 参数；coeffModulusBits 可自定义（对应 SEAL 的 CoeffModulus::Create）。 */
    public static native List<byte[]> genEncryptionParameters(int polyModulusDegree, long plainModulus,
                                                              int[] coeffModulusBits);

    /** 数据库预处理：按 Paterson-Stockmeyer 低次幂做明文分解，返回 NTT 域明文。 */
    public static native List<byte[]> processDatabase(byte[] encryptionParameters, long[][] coeffs, int psLowDegree);

    /** 计算密文查询的加密幂 —— 需要重线性化密钥（即密文×密文 + 重线性化）。 */
    public static native List<byte[]> computeEncryptedPowers(byte[] encryptionParameters, byte[] relinKeys,
                                                             List<byte[]> encryptedQuery, int[][] parentPowers,
                                                             int[] sourcePowers, int psLowDegree);

    /** Paterson-Stockmeyer 匹配（快）。 */
    public static native byte[] optComputeMatches(byte[] encryptionParameters, byte[] relinKeys,
                                                  List<byte[]> plaintextPolys, List<byte[]> ciphertextPolys,
                                                  int psLowDegree);

    /** 朴素匹配（慢，用于对照）。 */
    public static native byte[] naiveComputeMatches(byte[] encryptionParameters, List<byte[]> plaintextPolys,
                                                    List<byte[]> ciphertextPolys);

    /** 加密一个任意明文查询矩阵。 */
    public static native List<byte[]> generateQuery(byte[] encryptionParameters, byte[] publicKey, byte[] secretKey,
                                                    long[][] plainQuery);

    /** 解密服务端应答。 */
    public static native long[] decodeReply(byte[] encryptionParameters, byte[] secretKey, byte[] serverResponse);
}
