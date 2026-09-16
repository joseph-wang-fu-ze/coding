# RLWE 层（Java 实现）

> ## ⚠️ 不要在新代码里使用本模块 —— 请改用 MPC4J
>
> **本模块已降级为"交叉校验工具 + 大模数实验台"，不再是主路径。**
> 新实现一律架在 **MPC4J 的 BFV** 上（见 `coding/rgsw-lab/Mpc4jRgsw.java`）。
>
> **为什么改主意**：协议级运算 MPC4J 全是现成且成熟的，而本模块缺
> **"缩放回落"（CtCtMul 必需）、BatchEncoder、槽位旋转**这三块；
> 补齐需要几百行高难度代码，实测已卡在"缩放回落"上（见本文档第六节）。
>
> **保留它的两个用途**：
> 1. **交叉校验**——两个独立实现算同一件事，不一致就说明有 bug
>    （本轮靠这条抓出过 Shoup 常数溢出、逆变换丢归一化）；
> 2. **跑大模数**——只有它能到 N=16384 / 15 素数 / **451 位**，
>    MPC4J 在 9 素数就因 Galois 工具的内存分配 OOM。
>
> **何时仍该用它**：需要系数级控制做实验、或需要论文量级（438 位）模数验证时。
> 其余情况一律用 MPC4J。

> 位置：`coding/rlwe-java/`　包名：`com.fusepir.rlwe`
> 定位：CAPE 复现里 **RLWE 数据/累加器层** 的独立实现，被 `coding/rgsw-lab/` 依赖。
> 与 `coding/lwe-java/`（LWE 层）、`coding/rgsw-lab/`（RGSW 层）并列。
> **零外部依赖**：只用 JDK，`javac` 直接编译，可打成 `rlwe.jar`。

---

## 一、目录与文件

```
coding/rlwe-java/
├── run.ps1                 一键编译 / 自检 / 打包
├── rlwe.jar                编译产物（run.ps1 jar 生成）
└── src/main/java/com/fusepir/rlwe/
    ├── RingParams.java       参数：q（大整数）、多素数、gadget、NTT 上下文、CRT 逆元
    ├── RingOps.java          环运算：加/减/乘、三元专用乘法、小系数快路径、CRT 还原、采样
    ├── NttContext.java       负循环 NTT + NTT 友好素数生成
    ├── RlweCiphertext.java   密文 (c0, c1)
    ├── RlweKey.java          私钥 + 私钥 NTT 缓存
    ├── RlweOps.java          加解密、编码/解码、相位、噪声
    └── RlweSelfTest.java     自检（4 项）
```

**共约 1000 行**，其中 RLWE 核心 858 行。

---

## 二、怎么用

```powershell
cd E:\学习\密码赛\coding\rlwe-java
.\run.ps1            # 4 项自检
.\run.ps1 scale      # N=16384、15 素数（论文模数规模）下再跑一遍，约 63 秒
.\run.ps1 jar        # 生成 rlwe.jar，供其他模块用
```

被别的模块调用（`coding/rgsw-lab/` 就是这么做的）：

```java
import com.fusepir.rlwe.*;

RingParams p = RingParams.lab();                    // 或 paperParams(16384, 15)
RlweKey key = new RlweKey(p, rnd);
RlweCiphertext ct = RlweOps.encryptScaled(p, key, m, rnd);
long[] back = RlweOps.decrypt(p, key, ct);
BigInteger noise = RlweOps.noiseNorm(p, key, ct, m);
```

`rgsw-lab/run.ps1` 会把本模块的源码一起编译（同一 package tree，不用先打 jar）。

---

## 三、主要 API

| API | 作用 |
|---|---|
| `RingParams.lab()` / `paperParams(N, primeCount)` | 参数：快测 / 论文模数规模 |
| `RlweOps.encryptScaled` / `decrypt` | 加解密（消息 ∈ Z_t） |
| `RlweOps.encryptRaw` / `encryptRawPrime` | 原始加密（不做缩放，RGSW 内部用） |
| `RlweOps.phase` / `noiseNorm` / `unscale` | 相位、噪声、解码（都返回/接受大整数） |
| `RingOps.mul` / `multiply` / `mulSmall` / `mulTernary` | 环乘法（NTT / 小系数快路径 / 三元专用） |
| `RingOps.crtPoly` / `toPrimePoly` / `crt` / `center` | 跨素数还原与反向拆分 |
| `RingOps.sampleUniform` / `sampleTernary` / `sampleNoise` | 采样 |
| `NttContext.forward` / `inverse` / `pointwise` | NTT（一般不用直接调） |

---

## 四、参数与实测

| 参数 | lab | paper-like |
|---|---|---|
| N | 1024 | **16384** |
| 素数个数 / q | 1 × 31 位 | **15 × 31 位 = 451 位** |
| t | 65537 | 65537 |
| gadget 基数 B / 层数 l | 4 / 16 | 2¹⁶ / 29 |

实测：

```
[lab]        4 项自检全过；新鲜密文噪声 = 2，上限 8191
[scale]      N=16384、15 素数、q=451 位：4 项自检全过，63 秒
             （其中大部分是 Test 1 的"朴素乘法对照"，不是日常路径的开销）
```

优化过的地方：NTT（自动挑 NTT 友好素数，挑不到自动回退）、私钥常驻 NTT 域、
CRT 逆元预计算、小系数快路径、三元专用乘法。

---

## 五、与 MPC4J（`mpc4j-crypto-fhe-seal`）的优缺点对比

### 5.1 先说结论

- **要功能齐全 / 要序列化 / 要槽位打包 → 用 MPC4J。**
- **要做 RGSW / 盲旋转 / 要跑论文量级的模数 → 用这套**（MPC4J 在这些点上缺能力或有实测障碍）。
- **忠实复现论文性能 → 最终还是要 MPC4J + native**（作者就是用这个）。

### 5.2 能力对比

| 能力 | 本实现 | MPC4J `crypto-fhe-seal` |
|---|---|---|
| BFV 加解密 | ✅ | ✅ |
| 环乘法 / NTT | ✅ | ✅（更成熟） |
| **重线性化** | ❌（**不需要**：外部乘积是"密文 × 公开数字多项式"，结果仍是二元密文） | ✅ |
| **Galois / 按步数旋转** | ❌（用**公开单项式旋转**替代，见 `rgsw-lab/MonomialOps`） | ✅ |
| **RGSW 密文** | ❌（在 `rgsw-lab` 里） | ❌ **完全没有** |
| **外部乘积（RGSW ⊗ RLWE）** | ❌（在 `rgsw-lab` 里） | ❌ **完全没有** |
| **BlindRotate / SampleExtract / Pack** | ❌（待做） | ❌ **完全没有** |
| **跨素数还原 + 按 B 切段** | ✅ `RingOps.crtPoly` + `rgsw-lab/RgswOps.decompose` | ⚠️ C++ 侧有（`TFHERNS::CRTDecPoly`），**Java 侧没有公开入口** |
| 密钥切换 | ❌ | ⚠️ `switch_key_inplace` 是 **private**；`KswitchKeys` 源码注明"正常用户不应实例化" |
| BatchEncoder（槽位打包） | ❌ | ✅ |
| CKKS | ❌ | ✅ |
| 序列化 / 通信量统计 | ❌ | ✅ |
| 原生 C++ 加速 | ❌ | ✅（`mpc4j-native-fhe`，但 Windows 要自己补 CMake 的 WIN32 分支） |

### 5.3 工程与运行条件对比

| 项 | 本实现 | MPC4J |
|---|---|---|
| 依赖 | **零**（纯 JDK） | 11 个 jar（slf4j / guava / bcprov / trove4j / zstd-jni …） |
| 构建 | `javac` 一条命令 | Maven（**JDK 25 + source17 会冲突**，9/15 是靠绕开 Maven 用 javac 解决的） |
| 可打包 | ✅ `rlwe.jar`（33 KB） | 多模块，打包较重 |
| 代码可读性 | 高（每处都写了"为什么"） | 低（SEAL 移植，层层封装） |
| 中间量可观测 | ✅ 相位/噪声/切段数字都能打印，Test 1 能拿 NTT 与朴素乘法**逐位对比** | ❌ API 不暴露这些 |
| **N=16384 + 9 素数能否建上下文** | ✅ 能（本实现没有 Galois 预计算） | ❌ **实测 OOM**：`AbstractGaloisTool` 第 64 行每层分配 N² 个整数（≈1 GB/层，9 层 ≈ 9 GB）；2/4 素数可以 |
| 已跑到 | N=16384、**15 素数、451 位** | 冒烟测试 N=8192（9/15） |
| 安全性 | ❌ **完全没有**（实验台，不可用于真实场景） | ⚠️ 参数按 128-bit 安全，但本实现的用法也未做安全审计 |
| 与论文技术栈一致性 | ❌ 自研 | ✅ **作者就是用 MPC4J + native** |

### 5.4 一句话取舍

| 你的目标 | 选谁 |
|---|---|
| 验证 RGSW / 盲旋转的**逻辑正确性** | **本实现**（可对照、可打印、能跑大模数） |
| 做**参数扫描 / 性能实验** | **本实现**（params.env 改文件不改代码） |
| 要**序列化 / 量通信量 / 槽位打包** | **MPC4J**（本实现缺，需要补） |
| 要对标论文**性能数字** | **MPC4J + native**（本实现是纯 Java 且非论文技术栈） |
| 要**长期维护** | **MPC4J**（社区/文档/完整性），把本实现验证过的逻辑搬过去 |

---

## 六、已知缺口（**"后续完全能用"还差这些**）

| # | 缺什么 | 为什么必须要 | 成本 |
|---|---|---|---|
| 1 | **密文 × 密文乘法（CtCtMul）** | CAPE 的列选择与加密 Bloom 得分都是密文×密文（论文 Algorithm 2 第 4 行明确是 `CtCtMul`） | 约 30 行（NTT 域三次乘法） |
| 2 | **重线性化** | CtCtMul 产生三元密文，必须重线性化回二元 | 约 60 行（**可复用已有的切段机制**：生成 s² 的重线性化密钥，把 c2 切段累加） |
| 3 | **槽位打包 + 槽位旋转** | Bloom 内积是"逐位相乘再旋转求和"，属于槽位域运算 | 约 180 行（BFV batch 编码 + Galois 密钥 + 旋转后 key switch） |
| 4 | **序列化 + 通信量统计** | CAPE 要报 query/response 大小 | 约 80 行 |

**不打算补**：Galois 旋转的通用形式（用公开单项式旋转 `rgsw-lab/MonomialOps` 覆盖）、CKKS。

1. **序列化 + 通信量统计** —— CAPE 要报 query/response 大小，现在量不了；
2. **槽位打包（BatchEncoder 等价物）** —— CAPE 的加密 Bloom 内积如果走槽位就需要；
3. RLWE 侧模数切换 —— LWE 侧已实现（`lwe-java`），RLWE 侧还没做；
4. 多线程 —— 不急。

**不打算补**：重线性化、Galois 旋转、CKKS —— 本案用不到（原因见 5.2 表格）。
