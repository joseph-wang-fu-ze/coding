# LWE ↔ RLWE 桥实测 + 三步进度（2026-09-19）

> 目标（用户要求）：把三步做完 —— ①`LWEtoRGSW` ②整条链（逐位 LWE → RGSW → 盲旋转 → SampleExtract）
> ③高精度 `BitDecomp`。本文记录已完成部分与尚未完成部分，以及**为什么**。

---

## 一、已完成并验证 ✅

### 1. `SampleExtract_j`（论文原文：取出第 j 个系数，输出同密钥下的 LWE 样本）

实现：`LweRlweBridge.sampleExtract`。**系数约定是 reverse**：

```
b   = c0[j]
a_k = c1[(j−k) mod N]，当 (j−k) < 0 时取负（因为负循环环里跨过 X^N 等价于变号）
```

这个约定是**实测判定的**，不是推出来的。

### 2. `Pack`（论文原文：把 LWE 密文的消息打包进 RLWE 密文）

实现：`LweRlweBridge.packFromSample`，即上面映射的**逆**。当 LWE 密钥就是 RLWE 密钥
（LWE-in-RLWE）时，打包只是系数摆放，**不需要任何密钥切换** —— 这正是 CAPE 能让
"查询 = 1 个密文"的原因。

### 3. 整条链（除控制位的来源外，全部打通）

```
逐位 RGSW 控制位 ──► 盲旋转（14 轮 CMUX）──► SampleExtract_0 ──► Pack ──► 解密
```

实测（N=2048）：

| 测试 | 结果 |
|---|---|
| SampleExtract → Pack → 库解密 往返一致（抽查 0、1、7、1234、N−1） | ✅ 错 0 个 |
| 整条链：index=1234 → 读回 235 = p_index | ✅ |

## 二、一个方法论的坑（重要，被它骗过一次）

最初我用 `b + ⟨a,s⟩ ≡ c0[j] + (c1⊛s)[j] (mod p)` 来"验证" SampleExtract。
**这是同义反复**：换元后左右两边是同一个和式，只能证明自己索引自洽。
它当时"通过"了，而真正的解密测试失败 —— 这就是发现问题的路径。

**正确做法**：把抽出的 LWE 样本 **Pack 回 RLWE，交给库自己的解密器读**，
结果必须等于原密文在该系数上的解密值。这样同时验证了两个原语，且**不需要私钥的系数形式**。

顺带查清：MPC4J 的 `SecretKey.data()` 给的是 **NTT 域**（实测系数是 ≈q 的大数，
不是 ±1/0 的三元小值），所以自己算 ⟨a,s⟩ 一定错；Pack + 库解密正好绕开。

## 三、尚未完成 ❌（两步都卡在同一个东西上）

### ① `LWEtoRGSW` —— 本质是 **circuit bootstrapping**

Pirouette 原文：

> **LWEtoRGSW(LWE_s(b)) → RGSW_{N,Q}(b)** converts an LWE encryption of a bit b ∈ {0,1} into an
> RGSW ciphertext. **This operation is also known as circuit bootstrapping [35]**, and the
> state-of-the-art construction [94] includes basic operations such as blind rotations and
> homomorphic automorphisms.

**为什么不能简单实现**：我们的外部乘积依赖"group 的相位是**未乘 Δ 的原始 `g_i·b`**"这一约定
（见 `Mpc4jRgsw` 的推导）。要从"加密比特 b"得到相位为 `g_i·b` 的密文，等于要
"**按 b 选择是否加上常数 g_i**"——而"按加密比特选择"本身就是 CMUX/RGSW 提供的操作，
**是循环的** ✗。所以只能走 [94] 那套：用专门打包的测试多项式做一次盲旋转 +
同态自同构，把各个 `g_i` 分量一次性造出来。

### ③ 高精度 `BitDecomp` —— Pirouette Alg.1/3

把**一条** `LWE(idx)` 在密文状态下拆成 `⌈log₂N⌉` 条逐位 LWE 密文。
成本约 `3·d` 次 BlindRotate（k = d·ν 位，ν = 5），比"逐位基"的 `2k` 次省。
参数见 Pirouette Table 3：`n_in=1300 → n_out=600`（维度变小）、`q_in=2³² → q_out=2¹²`、`B=2¹⁴`、`B_ksk=2³`。

### 两者的关系与共同前提

| 变体 | 客户端发什么 | 服务器要做什么 |
|---|---|---|
| **Pirouette / CAPE 主流程** | **一条** `LWE(idx)`（36 B） | ③ `BitDecomp` → ① `LWEtoRGSW` ×14 → 盲旋转 |
| **PirouetteH**（省掉 ③） | **逐位** `{LWE(idx_i)}`（60 B） | ① `LWEtoRGSW` ×14 → 盲旋转 |

**关键**：`PirouetteH` 只是省掉 ③，**①在两条路里都必需**，而且 Pirouette 明说它贵
（"the expensive LWEtoRGSW operation needs to be performed for each bit of the query index"）。

**为什么不能用"客户端直接发 RGSW 控制位"代替 ①**：本项目的测试就是这么搭的脚手架，
但 RGSW 一个 50 MB（ℓ=25），14 个 = **700 MB** 的查询 ✗；
即便按 Pirouette 的 ℓ_rgsw=8 也是 224 MB ✗。所以它只适合做**正确性脚手架**，
不能替代协议消息。

### 两者的共同前提

`BitDecomp` 与 `LWEtoRGSW` 都需要**一把自举密钥 BK = {RGSW(s_i)}**（把 LWE 密钥 s 连到 RLWE 密钥上）。
好消息：这把钥匙由**客户端在 setup 阶段生成**（密钥持有者才能造 RGSW），
属于公开评估密钥的一部分 —— 这与论文/Pirouette 的做法一致，不是额外的新东西。

## 四、下一步的具体做法（已可执行）

现在手上已经齐了造 ① 所需的三块砖：**盲旋转**（`BlindRotateOps`）、
**SampleExtract**、**Pack**（`LweRlweBridge`）。于是 ① 可以这样落地：

1. 用 BK 做一次盲旋转，测试多项式取"舍入函数"（高半区为 1、低半区为 0），
   输出 RLWE 的系数即为 b 的指示函数（因 `β = ⟨a,s⟩ + Δ·b`，高半区对应 b=1）；
2. 把 gadget 常数按底 `t` 拆成"打包在系数上"的形式，
   用 `multiplyPlain`（公开常数，天然无需密钥）把指示函数缩放成 `b·g_i` 的各分量；
3. `SampleExtract` 逐系数取出，再用 `Pack` 组装成 `group0`/`group1` 的各个密文；
4. 用 `RGSW(1) ⊗ c = c` 与 `RGSW(0) ⊗ c = 0` 两条既有测试验收（它们正是能抓出这类错误的用例）。

③ 则在 ① 之上实现：`BasicBitDecomp`（Alg.1：1 次 BlindRotate + 乘 LWE + SampleExtract）
组合成 Alg.3，参数对齐 Pirouette Table 3。
