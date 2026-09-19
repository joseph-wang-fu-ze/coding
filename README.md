# `coding/` —— CAPE / FusePIR 的 Java 复现

> **硬约束**：不能改变原论文的算法（`Submission_usenix_232.pdf` / USENIX'232）。
> 参数与实现可以自选，但**必须记录在案**。
>
> **默认路线**：**B —— 纯 Java**（`lib/` 里那个 MPC4J SEAL 移植版 + 我们打的 Galois 补丁）。
> 另有 native 对照路线（真 SEAL 4.0.0，仅用于性能对照与交叉校验）与已弃用的自研路线。
> 三者的边界见 [`默认实现一览.md`](默认实现一览.md)，路线审计见 [`RLWE路线审计.md`](RLWE路线审计.md)。

本文按论文的协议四步组织：**SETUP → QUERY → ANSWER → DECODE**。

---

## 〇、四步 ↔ 代码总览

| 步骤 | 论文里做什么 | 对应代码 | 状态 |
|---|---|---|---|
| **SETUP** | 选参数；生成 HE 密钥与**评估材料**；数据库预处理（BFF + Bloom + 载荷编码） | 明文侧：`cape-fusepir-database-handoff/`<br>密钥材料：`rgsw-lab/`、`lwe-java/` | 🟡 原语齐、**缺 LWEtoRGSW 材料** |
| **QUERY** | 哈希 → BFF 位置 → 坐标 `(c_a,r_a)` → 位串 `z_a` → 逐位加密 `(ρ, {β})`；加密 Bloom 查询 | `lwe-java/`（LWE 加密 ✓）<br>`rgsw-lab/`（Pack 单系数 ✓） | 🔴 **客户端查询逻辑未实现** |
| **ANSWER** | 取列 + **BlindRotate** + `SampleExtract_0` + Bloom 打分（`CtCtMul` + `Σ CtRotate(·,2^r)`）+ 响应组装 | `rgsw-lab/` | 🟡 **原语全部实测可用**；流程编排与位口径缺 |
| **DECODE** | 解密 + BFF 重构（k=3 相加）+ 指纹校验 + 载荷解析（+ 合取阈值 τ） | 明文侧结构 ✓ | 🔴 **密文侧解码未实现** |

**一句话现状**：**四步里所有"密码学原语"都已在论文参数下验证过（N=16384），缺的是把它们按协议串起来的流程**；唯一的硬障碍是 `LWEtoRGSW`。

---

## 一、项目结构

| 目录 | 定位 | 关键文件 |
|---|---|---|
| **`lib/`** | 默认路线的库：MPC4J 的 SEAL **Java 移植版**（**已打补丁**）+ 11 个运行期依赖 | `mpc4j-crypto-fhe-seal.jar`、`deps/` |
| **`patches/`** | 对第三方库的补丁 | `mpc4j-galois-lazy-permutation-tables.patch`（**没有它 N=16384 必 OOM**） |
| **`rgsw-lab/`** | **主实验场**：所有已实现的子程序 + 自检 + 实测文档 | 见下表 |
| **`lwe-java/`** | **LWE 层**（包 `cape.he`）。MPC4J 全仓库没有 LWE，所以这是自研的 | `LWE.java`、`LWEParams.java`、`ModSwitchTest.java` |
| **`cape-fusepir-database-handoff/`** | 数据库预处理（**明文侧**）：BFF 布局、Bloom 过滤器、载荷编码、MovieLens 载入 | `DatabasePreprocessor.java`、`BloomParameters.java`、`PlaintextPayload.java` |
| **`native-jni/`** | 🔵 **对照路线**：真 SEAL 4.0.0 的 JNI 封装（`mpc4j-native-fhe.dll`） | `SealPirNativeTest`、`seal_params_probe.cpp` |
| **`rlwe-java/`** | ❌ **已弃用**：自研 RLWE（缺缩放回落，密文×密文做不出可用结果），仅作交叉校验 | — |
| `param-probe/`、`rlwe-bench/` | 测量工具（参数位宽、性能对照） | — |
| `pdf-extract/` | 三份 PDF 的**按栏切分**提取文本（原始提取是错行的） | `out_cape.txt`、`out_bkpir.txt`、`out_survey.txt` |
| `ml-latest-small/` | MovieLens 数据集（测试数据） | — |

`rgsw-lab/` 内部（**主实验场**）：

| 文件 | 实现的子程序 |
|---|---|
| `Mpc4jRgsw.java` | `RLWE.Enc/Dec`、`CtCtAdd`、`CtPtMul`、**`CtRotate`**、`RGSW.Enc`（常数与一般多项式）、外部乘积、`CMUX` |
| `Mpc4jCapability.java` | 四项能力探针（打包 / ct×ct+重线性化 / 旋转 / 模数切换） |
| `BlindRotateOps.java` | **`BlindRotate`** 两种口径（论文位口径 / 经典 d 轮口径） |
| `BlindRotateComplete.java` | 完整盲旋转（真实载荷 + 加密索引，端到端 4 项验收） |
| `LweRlweBridge.java` | **`SampleExtract_j`** + **`Pack`**（互逆映射，同一文件） |
| `LweToRgswOps.java` | **`LWEtoRGSW`**（❌ 未通过） |
| `RgswPolyTest.java`、`RgswPolyDiag.java` | 一般多项式 RGSW 的验证与诊断 |
| `RgswOps.java` 等 8 个 | ❌ **路线 C 遗留**（自研），已加弃用横幅 |
| `run-mpc4j.ps1` | 默认自检入口（`-Class` 可指定主类） |
| `run.ps1` | ❌ 路线 C 入口（顶部有 `LEGACY` 警示） |

---

## 二、SETUP

**论文要求**（§2.5、算法 1/4/5 SETUP）：选公开参数 `(N,d,t,q)`；生成 `sk=(s_L,s_R)`；
生成**评估材料**——重线性化密钥、Galois 旋转密钥、自举密钥、以及**`LWEtoRGSW` 所需材料**
（算法 4 第 2 行明确写了这一步）；数据库侧构造 BFF（k=3 位置、段长 s、总长 `L_BFF ≈ 1.125n`）、
每个值的 Bloom 过滤器、载荷 `y_K = fp(K) ‖ m_i ‖ v_1 ‖ … ‖ v_m ∈ Z_t^{B_pay}`。

**已有** ✅

| 项 | 位置 | 实测 |
|---|---|---|
| RLWE 密钥、上下文 | `Mpc4jRgsw` 构造函数 | N=16384 起效，`describe()` 打印声明/工作素数 |
| 重线性化密钥 | MPC4J `createRelinKeys` | 215 ms |
| **旋转密钥** | MPC4J `createStepGaloisKeys` | 118 ms；**论文只需 `{1,2,4,…,ℓ_BF/2}` 共 log₂ℓ_BF = 14 个步长**（由算法推得） |
| **自举密钥** `BK={RGSW(s_i)}` | `encryptRgswConstant` | 是盲旋转的 setup 材料 |
| `enc_sk = RGSW(s(X))` | `encryptRgswPoly` | 让服务器**能在不知道 s 的前提下乘上 s** |
| LWE 密钥（二进制） | `lwe-java` `keyGenBinary` | 200/200 |
| 数据库预处理（明文侧） | `cape-fusepir-database-handoff/` | 含测试 |

**缺** ❌

1. **`LWEtoRGSW` 的评估材料**——论文算法 4 第 2 行要求的东西，且该子程序本身未通过（见 ANSWER）。
2. **密钥/材料持久化**：setup 产物落盘、跨进程复用（现在全在内存里）。
3. **明文侧预处理接进密文流水线**：载荷如何摆进 RLWE 累加器（列布局）尚未定。

---

## 三、QUERY

**论文要求**（算法 4/5 QUERY）：

```
ℓ_c = ⌈log₂C⌉,  ℓ_r = ⌈log₂R⌉,  ρ ← {0,1}^λ
for a = 0..2:  u_a = h_a(K),  r_a = u_a mod R,  c_a = ⌊u_a/R⌋
               z_a = bin_ℓc(c_a) ‖ bin_ℓr(r_a)
               for j:  a_{a,j} ← PRG(ρ,a,j) ∈ Z_q^d
                       β_{a,j} ← ⟨a_{a,j}, s_L⟩ + Δ·z_a[j] + e   (mod q)
q = (ρ, {β_{a,j}})
```

**线上只传种子 ρ 与各 β**（压缩变体查询仅 **0.16 KiB**）；另有**定长**的加密 Bloom 查询
（= **1 个 RLWE 密文**，2304.97 KiB，由"查询恒为 2304.97 KiB"反推得到）。

**已有** ✅：LWE 加密（含二进制密钥、模数切换、`q_L = 2N` 预设）；`Pack` 的**单系数**版本。

**缺** ❌

1. **客户端查询逻辑本身**（哈希 → BFF 位置 → 坐标 → 位串 → 逐位加密 → `(ρ,β)` 打包）；
2. **多维/批量 `Pack`**：一次打包一批 LWE 样本到密文槽位（含容量规划）；
3. **加密 Bloom 查询的定长构造**；
4. **查询序列化**（线上格式、0.16 KiB 那一档）。

---

## 四、ANSWER

**论文要求**（图 1 + 算法 2）：取锚关键字对应的列 → **BlindRotate** 把目标条目转到常数位
（**行位驱动位驱动求值**）→ `SampleExtract_0` 取出 → Bloom 打分
`ct_score ← CtCtMul(q_BF, ct_BF)`，再 `Σ_r (ct_score + CtRotate(ct_score, 2^r))`（r = 0..log₂ℓ_BF−1）
求 Hamming 权重 → 响应组装（候选值 + 分数）并 `Pack`。

**已有** ✅（**全部在 N=16384 论文参数下实测**）

| 子程序 | 实测 |
|---|---|
| `CtCtAdd` / `CtPtMul` | ✅ |
| **`CtCtMul`**（含重线性化 + BFV 缩放回落） | ✅ 346+143 ms，0/16384 错位 |
| **`CtRotate`** | ✅ 85 ms（另 `rotateRows` 也通过） |
| 模数切换 | ✅ 9→8 素数，噪声 368→316 bit |
| **`RGSW.Enc`**（常数 + 一般多项式） | ✅ `RGSW(1)⊗c=c`、`RGSW(0)⊗c=0`、`RGSW(m)⊗c = m⊛msg` 全 0 错位 |
| 外部乘积 / `CMUX` | ✅ 726 ms / 688 ms |
| **`BlindRotate`** 位口径 | ✅ 常数位 = p_index，整条 16384/16384 一致 |
| **`BlindRotate`** 完整版（真实载荷 + 加密索引） | ✅ **4/4**（d=64：自举密钥 3.2 GB、盲旋转 116.9 s） |
| **`SampleExtract_j`** / **`Pack`** | ✅ 往返 5 个系数 0 错 |
| 噪声余量（ct×ct 后） | ✅ **339 bit**（N=4096 时只有 24 bit） |

**缺** ❌

1. **`LWEtoRGSW`**——论文的位口径卡在它上面（详见下节）；
2. **Bloom 打分的流程编排**（`CtCtMul` + `Σ CtRotate(·,2^r)` 的循环）；
3. **二维布局（BFF 的 R×C）与折叠**（Pirouette Phase 1-3）；
4. ⚠️ **轮数口径**：现在按 `⌈log₂N⌉`，论文要求按**行位** `⌈log₂R⌉`；
5. ⚠️ **RGSW 层数 ℓ=25**（Pirouette 是 8）：受"切段数字必须以明文喂进 `multiplyPlain`、
   明文窗口只有 ±t/2"限制 → 每个 RGSW 50 MB。改用 **RNS 切段**可降到约 13 层（体积/耗时约减半）；
6. ⚠️ 当前唯一"完全跑通"的是 **d 轮口径**，其自举密钥 = d×RGSW（d=512 时约 **25.6 GB**）→
   **功能完整但不可实用**；论文的位口径才能到 ⌈log₂R⌉ 个 RGSW（≈700 MB）。

### 唯一的硬障碍：`LWEtoRGSW`

| 项 | 说明 |
|---|---|
| 论文定义 | `LWEtoRGSW(ct_L) → C_μ`：给定 `LWE.Enc_s(μ)`（μ ∈ {0,1}），输出 `RGSW.Enc_s(μ)` |
| 本质 | Pirouette 原文：*"also known as **circuit bootstrapping**... includes basic operations such as blind rotations and homomorphic automorphisms"* |
| 已实现 | 三步结构（盲旋转取 μ → `(g_i·Δ⁻¹)·RLWE(μ)` → `⊗enc_sk` 造 group1）|
| 卡点 1（可修） | 取比特的**测试多项式约定**：`Δ=q_L/2` 时 μ=0/1 的相位只差一个**符号**，需用"窗口多项式 + 符号→比特的公开线性映射" |
| 卡点 2（本质） | **常数相位打包**：盲旋转输出"常数位=μ、其余系数是垃圾"，而 RGSW 要求相位**恒为 μ**；这一步正是 [94]（Wang 等, EUROCRYPT 2024）用同态自同构做的部分 |
| 现成实现 | ❌ MPC4J 的 `mpc4j-native-fhe/tfhe/` 只有 `RGSW.Enc(明文)` + 外部乘积 + RNS 切段，**没有 LWE→RGSW**；SEAL 完全没有自举 |
| **可能的绕道** | **OnionPIR 式**：把查询扩展成 gadget 缩放副本（公开旋转）+ 每份 `⊗enc_sk` 补 `·s` → 拼出 RGSW 形态，**不需要 LWEtoRGSW**。MPC4J 有现成 C++ 代码可抄，且我们缺的原语（`encryptRgswPoly`）已补齐；**但"能否按位工作"尚未验证**（需读 `poc_rlwe_expand` 的实现）|

---

## 五、DECODE

**论文要求**：解密候选值密文与分数密文 → **BFF 重构**（把 k=3 个位置的值**分量相加 mod t**）
→ **指纹校验**（fp = 40 bit）→ **载荷解析**（按 `f=⌈m/N⌉`、`ℓ=⌈max|v|/t⌉` 切出 m 个值）
→ 合取时用**本地保留的阈值 τ**（查询 Bloom 的汉明重量）判定候选。

**已有** ✅：明文侧的数据结构与解析逻辑（`cape-fusepir-database-handoff/`，含测试）；
客户端可解密（库解密器 + `decryptSampleViaPack`）。

**缺** ❌：密文侧解码流程的编排（解密 → BFF 重构 → 指纹 → 解析）；合取的阈值判定；
四步串起来的端到端联调。

---

## 六、参数现状

| 参数 | 值 | 来源 |
|---|---|---|
| `t` | 65537 | ✅ 论文 §5.1 |
| `N` | 16384 | ✅ 论文 §5.1 |
| 系数模数 | 声明 9 素数 / 438 位；**工作层 8 素数 / 389 位**（BFV 留最后一个素数作 `q_last`） | 论文只说"SEAL 默认"；位数我们实测补出 |
| BFF `k` / 指纹 / `ε_BF` | 3 / 40 bit / 2⁻²⁰ | ✅ 论文 §5.1 |
| `ℓ_BF` | = N = 16384 | ⚠️ 由"查询恰为 1 个密文"反推 |
| `R`、`C`、`ℓ_c`、`ℓ_r` | `R ≤ N`、`RC ≥ L_BFF`；`ℓ_c=⌈log₂C⌉`、`ℓ_r=⌈log₂R⌉` | ✅ 约束是论文给的；**具体取值未定** |
| **`d`（LWE 维数）** | **512** | ⚠️ **论文没给**，取自 Pirouette Table 4 |
| `q_L` | `2N`（结构约束：盲旋转要求 q 为 2 的幂且 q=2N） | ✅ 推得 |
| `σ²` | 3.192（σ≈1.7866） | ⚠️ Pirouette |
| gadget 底 / 层数 | 现状 2¹⁶ / 25；（Pirouette：`B_rgsw=2²⁴`、`ℓ_rgsw=8`） | ⚠️ 有差距，见 ANSWER 缺项 5 |
| 旋转密钥步长集 | `{1,2,4,…,ℓ_BF/2}` = 14 个 | ✅ 由算法推得 |

---

## 七、所缺东西汇总（按优先级）

| # | 缺什么 | 影响到哪一步 | 难度 |
|---|---|---|---|
| 1 | **`LWEtoRGSW`**（或 OnionPIR 式替代） | ANSWER 的位口径 | **高**（研究级打包）；绕道待验证 |
| 2 | 客户端 QUERY 逻辑 + 多维 `Pack` | QUERY | 中 |
| 3 | 密文侧 DECODE 流程 + 阈值判定 | DECODE | 中 |
| 4 | Bloom 打分编排（`CtCtMul` + `Σ CtRotate`） | ANSWER | 低 |
| 5 | 二维布局（R×C）与折叠（Phase 1-3），行位轮数 | ANSWER | 中高 |
| 6 | RGSW 参数对齐（RNS 切段，ℓ 25→13，密钥 700→350 MB） | ANSWER 性能 | 中（算法已读懂） |
| 7 | 密钥持久化 + 四步端到端联调 | 全部 | 低 |
| 8 | 与 native 的同参数性能对拍 | — | 低 |

---

## 八、跑起来

```powershell
# 默认路线（纯 Java）—— 各项自检
cd coding\rgsw-lab
.\run-mpc4j.ps1                                                  # RGSW + CMUX 自检（5 项）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.Mpc4jCapability 16384    # 论文规模四项能力
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateOps 2048      # 盲旋转两种口径
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.RgswPolyTest 2048        # 一般多项式 RGSW
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.LweRlweBridge 2048       # SampleExtract / Pack
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.LweToRgswOps 2048 64     # LWEtoRGSW（当前预期失败）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateComplete 16384 64   # 完整盲旋转（论文规模，约 4 分钟）

# LWE 层（纯 JDK，无依赖）
cd coding\lwe-java
.\run.ps1

# 对照路线（真 SEAL）
cd coding\native-jni
.\run.ps1 -N 16384
```

前提：JDK（`D:\Java\jdk` 或 PATH 里的 `javac/java`）。默认路线**不需要任何 C++ 工具链** ✓。

---

## 九、文档索引

| 文档 | 内容 |
|---|---|
| `默认实现一览.md` | **哪条路线是默认、哪个文件夹放什么**（最容易被搞混的六处） |
| `RLWE路线审计.md` | 三条路线的逐文件判定、补丁带来的转折、论文规模实测结果 |
| `HE_三层调用说明汇总.md` | 三层（LWE / RLWE / RGSW）的关系与 API |
| `rgsw-lab/RGSW_调用说明.md` | RGSW 层的自检与参数；**踩坑记录**（七个坑 + MPC4J 新增的三个） |
| `rgsw-lab/BlindRotate_实测.md` | 盲旋转的论文定义原文、轮数口径修正、论文规模耗时 |
| `rgsw-lab/LWE_RLWE桥_实测.md` | SampleExtract / Pack 实测、`LWEtoRGSW` 的两个卡点、方法论警告 |
| `../CAPE_参数表.md` | 参数总表（论文给的 / 从 Pirouette 继承的 / 我们定的 / 实测的） |
| `SYNC.md` | 推送到远端的步骤与环境问题记录 |
