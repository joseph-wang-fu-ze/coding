package com.fusepir.nativejni;

import edu.alibaba.mpc4j.s2pc.pir.stdpir.index.seal.SealStdIdxPirNativeUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 用 MPC4J 自带的 native 封装（真 SEAL 4.0.0 C++）跑一遍 SealPIR 全流程，
 * 参数取论文那套：N=16384、t=65537、128 位安全（BFVDefault → 438 位模数）。
 *
 * <p>为什么这是关键验证：纯 Java 移植版在 N=16384 上<b>跑不起来</b>
 * （AbstractGaloisTool 每层模数分配 N² 个 int，约 1 GB/层 × 9 层）。这条 native
 * 路径如果能跑通，就说明"参数能达到论文规模"这个目标达成。
 *
 * <p>数据库布局：第 i 条记录的 N 个系数全部填同一个值（记为 v_i）。这样无论
 * 应答结果落在哪个系数上，只要选择正确，解密后整条明文都应当等于 v_target。
 */
public class SealPirNativeTest {

    private static int failed = 0;

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 16384;
        long t = args.length > 1 ? Long.parseLong(args[1]) : 65537L;
        int dbSize = args.length > 2 ? Integer.parseInt(args[2]) : 256;
        int target = args.length > 3 ? Integer.parseInt(args[3]) : 170;

        System.out.println("=== 真 SEAL 4.0.0（native）上的 SealPIR 全流程 ===");
        System.out.printf("[params] 请求 N=%d, t=%d, 数据库 %d 条, 目标下标 %d%n", n, t, dbSize, target);
        System.out.println();

        long t0 = System.nanoTime();
        byte[] parms = SealStdIdxPirNativeUtils.generateEncryptionParams(n, t);
        System.out.printf("[1] 生成 BFV 参数        %6d ms   序列化 %d 字节%n",
            ms(t0), parms.length);
        int expRatio = SealStdIdxPirNativeUtils.expansionRatio(parms);
        System.out.printf("    膨胀比 expansionRatio = %d%n", expRatio);

        t0 = System.nanoTime();
        List<byte[]> keys = SealStdIdxPirNativeUtils.keyGen(parms);
        System.out.printf("[2] 密钥生成(pk/sk/galois) %6d ms   pk %d B, sk %d B, galois %d B%n",
            ms(t0), keys.get(0).length, keys.get(1).length, keys.get(2).length);
        byte[] pk = keys.get(0);
        byte[] sk = keys.get(1);
        byte[] gk = keys.get(2);

        // 数据库：第 i 条记录的 N 个系数都填 (i % 1000) + 1
        List<long[]> db = new ArrayList<>(dbSize);
        for (int i = 0; i < dbSize; i++) {
            long[] entry = new long[n];
            Arrays.fill(entry, (i % 1000) + 1);
            db.add(entry);
        }
        t0 = System.nanoTime();
        List<byte[]> dbNtt = SealStdIdxPirNativeUtils.nttTransform(parms, db);
        byte[] dbRow = dbNtt.get(0);
        System.out.printf("[3] 数据库 NTT 预处理   %6d ms   %d 条, 每条明文 %d 字节%n",
            ms(t0), dbNtt.size(), dbRow.length);
        byte[][] database = dbNtt.toArray(new byte[0][]);

        t0 = System.nanoTime();
        List<byte[]> query = SealStdIdxPirNativeUtils.generateQuery(
            parms, pk, sk, new int[]{target}, new int[]{dbSize});
        System.out.printf("[4] 生成查询(加密)       %6d ms   %d 个密文, 每个 %d 字节%n",
            ms(t0), query.size(), query.get(0).length);

        t0 = System.nanoTime();
        List<byte[]> reply = SealStdIdxPirNativeUtils.generateReply(
            parms, gk, query, database, new int[]{dbSize});
        long replyMs = ms(t0);
        long replyBytes = 0;
        for (byte[] r : reply) {
            replyBytes += r.length;
        }
        System.out.printf("[5] 服务端生成应答       %6d ms   %d 个密文, 合计 %d 字节 (%.2f MB)%n",
            replyMs, reply.size(), replyBytes, replyBytes / 1048576.0);

        t0 = System.nanoTime();
        long[] got = SealStdIdxPirNativeUtils.decryptReply(parms, sk, reply, 1);
        System.out.printf("[6] 解密应答             %6d ms   %d 个系数%n", ms(t0), got.length);

        long want = (target % 1000) + 1;
        long wrong = 0;
        for (long v : got) {
            if (v != want) {
                wrong++;
            }
        }
        failed += report("SealPIR 往返：取回数据库第 " + target + " 条", wrong == 0,
            String.format("期望全 %d，错位 %d/%d（前 8 个系数：%s）",
                want, wrong, got.length, first(got, 8)));

        System.out.println();
        System.out.println(failed == 0
            ? "=== 结论：真 SEAL 在 N=" + n + " / " + t + " 上跑通 SealPIR 全流程 ==="
            : "=== 有 " + failed + " 项失败 ===");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }

    private static String first(long[] a, int k) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < Math.min(k, a.length); i++) {
            sb.append(i > 0 ? ", " : "").append(a[i]);
        }
        return sb.append("]").toString();
    }

    private static int report(String name, boolean ok, String detail) {
        System.out.println();
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        System.out.println("       " + detail);
        return ok ? 0 : 1;
    }
}
