package com.fusepir.nativejni;

import edu.alibaba.mpc4j.s2pc.pir.stdpir.index.seal.SealStdIdxPirNativeUtils;
import edu.alibaba.mpc4j.work.psipir.Lpzl24BatchPirNativeUtils;

import java.util.List;

/**
 * 探针：确认 coding/native-jni 里的两族绑定都能加载并可用，
 * 并且验证"自定义系数模数"这条对 CAPE 对齐论文参数很重要的能力。
 */
public class NativeApiProbe {

    public static void main(String[] args) {
        int n = 16384;
        long t = 65537;
        // SEAL 对 N=16384 的 128 位安全上限约 438 位，这里给 8 × 54 = 432 位，留安全余量
        int[] bits = {54, 54, 54, 54, 54, 54, 54, 54};

        System.out.println("=== native 绑定可用性探针 ===");
        System.out.printf("[params] N=%d, t=%d, 自定义系数模数 %d 个素数 × %d 位 = %d 位%n",
            n, t, bits.length, bits[0], bits.length * bits[0]);
        System.out.println();

        // 1) SealPIR 族的接口：类加载时 System.loadLibrary("mpc4j-native-fhe") 必须成功
        long t0 = System.nanoTime();
        byte[] parmsDefault = SealStdIdxPirNativeUtils.generateEncryptionParams(n, t);
        System.out.printf("[A] SealStdIdxPir.generateEncryptionParams   ok  %d ms, %d 字节, expansionRatio=%d%n",
            ms(t0), parmsDefault.length, SealStdIdxPirNativeUtils.expansionRatio(parmsDefault));

        // 2) Lpzl24 族：自定义系数模数
        List<byte[]> custom;
        try {
            t0 = System.nanoTime();
            custom = Lpzl24BatchPirNativeUtils.genEncryptionParameters(n, t, bits);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < custom.size(); i++) {
                sb.append(i > 0 ? ", " : "").append(custom.get(i).length).append(" B");
            }
            System.out.printf("[B] Lpzl24.genEncryptionParameters(自定义)     ok  %d ms, 返回 %d 项 [%s]%n",
                ms(t0), custom.size(), sb);
        } catch (Throwable e) {
            System.out.printf("[B] Lpzl24.genEncryptionParameters 失败: %s: %s%n",
                e.getClass().getSimpleName(), e.getMessage());
            return;
        }

        // 3) 两族是否共用同一套 SEAL 参数序列化：把 Lpzl24 生成的参数喂给 SealPIR 的 keyGen
        try {
            t0 = System.nanoTime();
            List<byte[]> keys = SealStdIdxPirNativeUtils.keyGen(custom.get(0));
            System.out.printf("[C] 用自定义参数做 keyGen（两族参数互通）      ok  %d ms, pk %d B, sk %d B, galois %d B%n",
                ms(t0), keys.get(0).length, keys.get(1).length, keys.get(2).length);
        } catch (Throwable e) {
            System.out.printf("[C] 参数互通性检查失败: %s: %s%n", e.getClass().getSimpleName(), e.getMessage());
        }

        System.out.println();
        System.out.println("=== 结论：两族 JNI 绑定都可用，且支持自定义系数模数 ===");
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }
}
