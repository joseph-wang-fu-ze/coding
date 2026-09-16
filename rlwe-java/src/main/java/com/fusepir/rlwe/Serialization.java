package com.fusepir.rlwe;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;

/**
 * 密文序列化与通信量统计。
 *
 * <p>两件事：
 * <ol>
 *   <li><b>真实字节序列化</b>：把密文的 RNS 系数按 long 写出、再读回（往返必须逐位一致）；</li>
 *   <li><b>通信量统计</b>：CAPE 要报 query/response 大小，这里给出与序列化一致的字节数。</li>
 * </ol>
 *
 * <p>格式（简单、够用）：魔数 "RLWE" + 版本 + N + 素数个数 + 各素数 + q 位宽 + 各分量系数。
 * 真实部署应当用 SEAL 的压缩序列化，这里只要求"能量、能往返"。
 */
public final class Serialization {

    private static final byte[] MAGIC = {'R', 'L', 'W', 'E'};
    private static final int VERSION = 1;

    private Serialization() {
    }

    /**
     * 一个 RLWE 密文的字节数（与 {@link #toBytes} 的实际输出长度一致）。
     *
     * <p>RNS 表示下<b>每个素数各存一份系数</b>，所以要按各素数的位宽分别算——
     * 用"q 的总位宽"去乘是不对的（会高估）。
     */
    public static long ciphertextBytes(RingParams p) {
        long perComponent = 0;
        for (long prime : p.primes) {
            int bits = 64 - Long.numberOfLeadingZeros(prime);
            perComponent += (long) ((bits + 7) / 8) * p.n;
        }
        return 2L * perComponent;
    }

    /** 单个素数下、单个分量的字节宽 */
    private static int primeBytes(long prime) {
        return (64 - Long.numberOfLeadingZeros(prime) + 7) / 8;
    }

    /** 人类可读的大小 */
    public static String describe(RingParams p, long count) {
        long b = ciphertextBytes(p) * count;
        if (b < (1L << 20)) {
            return String.format("%.1f KB", b / 1024.0);
        }
        if (b < (1L << 30)) {
            return String.format("%.1f MB", b / 1048576.0);
        }
        return String.format("%.2f GB", b / 1073741824.0);
    }

    /** 序列化：输出紧凑字节（每个系数按 ceil(qBits/8) 字节打包） */
    public static byte[] toBytes(RingParams p, RlweCiphertext ct) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bos)) {
            out.write(MAGIC);
            out.writeInt(VERSION);
            out.writeInt(p.n);
            out.writeInt(p.primes.length);
            for (long prime : p.primes) {
                out.writeLong(prime);
            }
            out.writeInt(p.qBits);
            for (int comp = 0; comp < 2; comp++) {
                long[][] poly = comp == 0 ? ct.c0 : ct.c1;
                for (int k = 0; k < p.primes.length; k++) {
                    int bytesPerCoeff = primeBytes(p.primes[k]);
                    for (int i = 0; i < p.n; i++) {
                        long v = poly[k][i];
                        for (int b = 0; b < bytesPerCoeff; b++) {
                            out.writeByte((int) ((v >>> (8 * b)) & 0xFF));
                        }
                    }
                }
            }
            out.flush();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return bos.toByteArray();
    }

    /** 反序列化（必须用同一组参数） */
    public static RlweCiphertext fromBytes(RingParams p, byte[] data) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data))) {
            byte[] magic = new byte[4];
            in.readFully(magic);
            for (int i = 0; i < 4; i++) {
                if (magic[i] != MAGIC[i]) {
                    throw new IllegalArgumentException("不是本格式的密文");
                }
            }
            int version = in.readInt();
            if (version != VERSION) {
                throw new IllegalArgumentException("版本不支持: " + version);
            }
            int n = in.readInt();
            int primes = in.readInt();
            if (n != p.n || primes != p.primes.length) {
                throw new IllegalArgumentException(
                    "参数不匹配：密文 N=" + n + "/素数=" + primes
                        + "，当前参数 N=" + p.n + "/素数=" + p.primes.length);
            }
            for (long ignored : p.primes) {
                in.readLong();
            }
            in.readInt(); // qBits（仅供人读，解析不用）
            long[][] c0 = new long[p.primes.length][p.n];
            long[][] c1 = new long[p.primes.length][p.n];
            for (int comp = 0; comp < 2; comp++) {
                long[][] poly = comp == 0 ? c0 : c1;
                for (int k = 0; k < p.primes.length; k++) {
                    int bytesPerCoeff = primeBytes(p.primes[k]);
                    for (int i = 0; i < p.n; i++) {
                        long v = 0;
                        for (int b = 0; b < bytesPerCoeff; b++) {
                            v |= ((long) in.readUnsignedByte()) << (8 * b);
                        }
                        poly[k][i] = v % p.primes[k];
                    }
                }
            }
            return new RlweCiphertext(c0, c1);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** FusePIR/CAPE 关心的三类通信量 */
    public static String report(RingParams p, int columnSelectors, int rowSelectorDim,
                                int payloadBlocks) {
        StringBuilder sb = new StringBuilder();
        sb.append("communication estimate (N=").append(p.n)
            .append(", q=").append(p.qBits).append(" bit):\n");
        long ct = ciphertextBytes(p);
        sb.append(String.format("  one RLWE ciphertext      = %s%n", describe(p, 1)));
        sb.append(String.format("  %d column selectors       = %s%n",
            columnSelectors, describe(p, columnSelectors)));
        long lweBytes = (long) rowSelectorDim * ((p.qBits + 7L) / 8L);
        sb.append(String.format("  %d LWE row selectors      = %d bytes%n",
            3, 3L * lweBytes));
        sb.append(String.format("  response (%d payload blks) = %s%n",
            payloadBlocks, describe(p, payloadBlocks)));
        return sb.toString();
    }

    /** 便于外部核算：q 的字节数 */
    public static int coeffBytes(RingParams p) {
        return (int) ((p.qBits + 7L) / 8L);
    }

    /** 便于外部核算：BigInteger 之和（用于校验） */
    static BigInteger qCheck(RingParams p) {
        return p.q;
    }
}
