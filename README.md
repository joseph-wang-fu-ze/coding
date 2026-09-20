# `coding/` —— CAPE / FusePIR 的 Java 复现

> **硬约束**：不能改变原论文的算法（`Submission_usenix_232.pdf` / USENIX'232）。
> 参数与实现可以自选，但**必须记录在案**。
>
> **默认路线**：**B —— 纯 Java**（`lib/` 里那个 MPC4J SEAL 移植版 + 我们打的 Galois 补丁）。
> 另有 native 对照路线（真 SEAL 4.0.0，仅用于性能对照与交叉校验）与已弃用的自研路线。
> 三者的边界见 [`默认实现一览.md`](默认实现一览.md)，路线审计见 [`RLWE路线审计.md`](RLWE路线审计.md)。
>
> **2026-09-19 基准整改**：复现基准定为 **CAPE（算法 2）**，锚检索走 **FusePIR（算法 1）**；
> **不实现 CAPE-C / FusePIR-C**。因此 `LWEtoRGSW` **不在关键路径上**（详见第〇节）。
> 同时**纠正列选择的语义**：它是**密文×明文**（`CtPtMul`），不是密文×密文（详见第一节）。

---

# 〇、总体实现依据（2026-09-19 定稿，先看这一节）

**本项目复现的是 `Submission_usenix_232/` 那篇论文里的 `CAPE`（算法 2），不是 `CAPE-C`（算法 5）。**

论文一共给了四个方案，一层套一层：

| 方案 | 论文位置 | 锚检索用谁 | 客户端发的选择器 | 需要 `LWEtoRGSW`？ |
|---|---|---|---|---|
| **FusePIR** | 算法 1（§3.1） | — | **RLWE one-hot 列选择器 + LWE 行选择器** | ❌ 不需要 |
| **CAPE** ← ✅ **我们的目标** | **算法 2（§4.1）** | `FusePIR.Answer` | 同 FusePIR，另加**加密 Bloom 查询向量** | **❌ 不需要** |
| FusePIR-C | 算法 4（附录 B） | — | 紧凑**种子化 LWE** 坐标 | ✅ 需要 |
| CAPE-C | 算法 5（附录 C） | `FusePIR-C.Answer` | 同 FusePIR-C，另加加密 Bloom 向量 | ✅ 需要 |

**依据一：CAPE 的锚检索调用的是 `FusePIR.Answer`，不是 `FusePIR-C.Answer`。**
算法 2 第 2 行原文：`resp_anc ← FusePIR.Answer(st_S^F, q_anc)`；
而算法 5（CAPE-C）才是 `resp_anc ← FusePIR-C.Answer(st_S, q_anc)`。

**依据二：`LWEtoRGSW` 是查询压缩变体专有的。**
附录 B 原文：

> Instead of directly sending the **RLWE one-hot column selectors and LWE row selectors**, the client sends
> compact seeded LWE encryptions of their binary coordinates. … The resulting LWE encryptions are converted
> to RGSW form by **`LWEtoRGSW`**; the column bits are then expanded into the encrypted one-hot selector,
> while the row bits drive the bit-wise evaluation of `BlindRotate`.

§2.5 对 `LWEtoRGSW` 的定义同样只说了一件事：

> `LWEtoRGSW(ct_L) → C_μ`：… converting the encrypted bit into the RGSW representation used for
> **selector expansion in the query-compressed variants**.

**结论（对旧文档的更正）：**

1. `LWEtoRGSW` **不必实现**，也不必为它去啃 circuit bootstrapping。它在 C 变体里才出现。
2. 旧文档"**唯一的硬障碍是 `LWEtoRGSW`**"这一结论**作废**——那是**误把 CAPE-C 的结构当成了目标**。
3. 真正的问题换成另一个（见第三节）：**CAPE 的盲旋转要用 `d` 个 RGSW 做自举密钥，`d=512` 时体积 25.6 GB**。
   这是工程成本问题，不是"某个原语没写出来"的问题。

---

# 一、列选择的正确定义（2026-09-19 纠正）

## 1.1 之前错在哪

旧文档写的是：「**CAPE 的列选择与加密 Bloom 得分都必须是密文×密文**（论文算法 2 第 4 行明确写 `CtCtMul`）」。
**前半句是错的。**

论文 §2.5 在给出四个同态操作后，紧接着写了一句把用途钉死的话：

> `CtCtAdd(ct_0,ct_1) → Enc(m_0+m_1)`,
> `CtPtMul(ct_0,m_1) → Enc(m_0·m_1)`,
> `CtCtMul(ct_0,ct_1) → Enc(m_0·m_1)`,
> `CtRotate(ct,i) → Enc(Rot(m,i))`.
> **The first two operations are used extensively in FusePIR for encrypted selection and reconstruction.
> CAPE additionally uses ciphertext–ciphertext multiplication and rotation to evaluate encrypted Bloom scores.**

即：

- **加密选择（列选择）与 BFF 重建 → 只用 `CtCtAdd` / `CtPtMul`（密文 × 明文）**；
- **`CtCtMul` 与 `CtRotate` → 只用于 CAPE 的加密 Bloom 得分**（算法 2 第 4~7 行）。

`CtCtMul` 出现在算法 2 里，但**不是**用在列选择上。

## 1.2 正确的列选择语义

1. **客户端**把列坐标 `c_a` 做成 one-hot 向量 `e_{c_a} = (0,…,1,…,0) ∈ {0,1}^C`，
   **把它的每一位当作明文多项式的一个系数**，然后**整体做一次 RLWE 加密**：

   ```
   q_col,a ← RLWE.Enc_{s_R}(e_{c_a})          ← 只发一个密文，不是"每位一个密文"
   ```

2. **服务端**把**数据库的每一列**打包成一个**明文多项式**（服务端本来就有明文 DB，这一侧不需要加密）：

   ```
   P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r + cR][b] · X^r        （算法 1 SETUP 第 14 行）
   ```

   论文原文（§3.1）：*"We further represent the array into a two-dimensional layout and **pack each
   column into polynomial coefficients**. This design allows the server to **select the target column
   homomorphically** and then extract the desired entry using the encrypted row index."*

3. 两者做**明文–密文同态内积**（`CtPtMul`，密文 × 明文）：

   ```
   Acc_{a,b} ← Σ_{c=0}^{C−1} CtPtMul(q_col,a[c], P_{c,b}(X))      （算法 1 ANSWER 第 5 行）
   ```

   —— `q_col,a[c]` 是"加密选择器的第 c 位"，`P_{c,b}(X)` 是"第 c 列"；求和就是内积，
   结果 `Acc_{a,b}` 是**被选中那一列**的加密。

4. **之后**才用**行选择器**做盲旋转，把目标行挪到常数位：

   ```
   Acc'_{a,b} ← BlindRotate(q_row,a, Acc_{a,b})                    （算法 1 ANSWER 第 6 行）
   ct_{a,b}   ← SampleExtract_0(Acc'_{a,b})                        （算法 1 ANSWER 第 7 行）
   ```

## 1.3 与旧理解的逐项对照

| 项 | ❌ 旧文档 | ✅ 正确 |
|---|---|---|
| 列选择的算子 | `CtCtMul`（密文×密文） | **`CtPtMul`（密文×明文）** |
| 列选择器的形态 | 每位一个 LWE 密文（再转 RGSW） | **一个 RLWE 密文**，one-hot 的每一位是**明文多项式的系数** |
| 数据库一侧 | 参与密文运算 | **是明文多项式**（每列一个），由服务端本地持有 |
| 行选择器的形态 | 逐位 LWE（`ℓ_r` 条） | **一条 `LWE.Enc(r_a)`**（不是逐位） |
| `CtCtMul` 用在哪 | 列选择 + Bloom 得分 | **只用于 Bloom 得分** |
| `LWEtoRGSW` 何时需要 | "CAPE 主流程必需" | **只有 C 变体需要** |

> **待与 artifact 对齐的一点（不阻塞主线）**：论文把内积写成 `C` 项之和，工程上可等价地压成
> **一次** `CtPtMul`——把整张表按列交错打进一个明文多项式、把选择器写成对应的负指数多项式即可。
> 两种写法在负循环环 `Z_t[X]/(X^N+1)` 里**符号约定**（`X^{−k} = −X^{N−k}`）必须逐位对拍；
> 落地时二选一，**以与作者 artifact 一致为准**。

---

# 二、整改需求（按优先级）

> 判定方式：**每一行都要能跑出一个"通过/不通过"的结论**。
> 状态：`✅ 已合规` / `🔧 待整改` / `⏸ 本次不做`

### R1. 基准结构从 CAPE-C 改回 CAPE（最高优先级）

| | |
|---|---|
| **论文依据** | 算法 2 第 2 行 `resp_anc ← FusePIR.Answer(...)`；附录 B「`LWEtoRGSW` … for the query-compressed variants」 |
| **现状** | README / `CAPE_子程序实现对照表.md` 把 `LWEtoRGSW` 列为"唯一硬障碍"，按 CAPE-C 的位口径组织 |
| **整改** | 文档基准改为 **CAPE = FusePIR + Bloom**；`LWEtoRGSW` 从缺项清单与实施顺序中移除，降为 `⏸ 仅 C 变体` |
| **验收** | README、对照表、实施顺序三处不再把 `LWEtoRGSW` 列为必需；不再出现"唯一硬障碍是 LWEtoRGSW"的表述 |

### R2. 列选择改为 `CtPtMul`（密文 × 明文），并纠正文档

| | |
|---|---|
| **论文依据** | §2.5「The first two operations [`CtCtAdd`/`CtPtMul`] are used extensively in FusePIR for encrypted selection」；算法 1 ANSWER 第 5 行 |
| **现状** | 文档把列选择当成 `CtCtMul`；实现里只做了底层算子，**没有 `selectColumn` 这一步** |
| **整改** | ①文档按第 1.2 节改写；②实现 `Acc = Σ_c CtPtMul(ct_col[c], P_{c,b}(X))`（或 1.3 的单次乘法等价式）；③把 `P_{c,b}(X)` 的二维列打包从明文侧接进密文流水线 |
| **验收** | 给定 `ct_col` 与 `{P_{c,b}}`，`Acc` 解密后**逐系数等于被选中列**；换 `c_a` 再验一次 |

### R3. 行选择器收敛为"单条 LWE 密文"，盲旋转用 d 轮口径

| | |
|---|---|
| **论文依据** | 算法 1 QUERY 第 4 行 `q_row,a ← LWE.Enc_{s_L}(r_a)`；§2.5 `BlindRotate(ct_L, ct_R)` 的第一个参数是 **LWE 密文** |
| **现状** | 两种口径都已实现并互验通过；但文档把 `blindRotateByBits`（逐索引位、控制位是 RGSW）称作"论文口径" |
| **整改** | 明确 **`BlindRotateOps.blindRotate`（d 轮、按秘密位）才是 CAPE 的口径**；`blindRotateByBits` 归给 **CAPE-C**（它的控制位来自 `LWEtoRGSW`） |
| **验收** | `BlindRotate(LWE.Enc(r_a), Acc)` 端到端跑通，常数位 = 目标行；接口签名与论文一致（**输入是 `(a,β)`，不是逐位 RGSW**） |

### R4. `CtCtMul` / `CtRotate` 的用途收敛到 Bloom 打分

| | |
|---|---|
| **论文依据** | 算法 2 第 4~7 行：`ct_score,j ← CtCtMul(q_BF, ct_j^BF)`，再 `for r=0..log₂ℓ_BF−1: ct_score,j ← CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r))` |
| **现状** | `CtCtMul`（346+143 ms、0/16384 错位）与 `CtRotate`（85 ms）**实测已就绪**，但**打分循环没写** |
| **整改** | 实现 `bloomScore(q_BF, ct_j^BF)`，即上面的乘 + 折叠相加循环；轮数 = `log₂ℓ_BF` |
| **验收** | 命中候选解密得分 = τ = ‖b_qry‖₁，不命中 < τ；用构造好的正反例各验一遍 |

### R5. 客户端 QUERY 逻辑按算法 1 第 2~5 行实现

| | |
|---|---|
| **论文依据** | `u_a ← h_a(K)`，`r_a ← u_a mod R`，`c_a ← ⌊u_a/R⌋`；`q_col,a ← RLWE.Enc(e_{c_a})`；`q_row,a ← LWE.Enc(r_a)`；`q_a ← (q_col,a, q_row,a)` |
| **现状** | LWE 加密 ✅、RLWE 加密 ✅、one-hot 构造 ❌（**且没有 `u_a → (c_a, r_a)` 的坐标拆分**） |
| **整改** | 实现坐标拆分 + one-hot 的 RLWE 加密 + `r_a` 的 LWE 加密 |
| **验收** | `(c_a, r_a)` 与 `u_a` 满足 `u_a = c_a·R + r_a`；`q_col,a` 解密后恰为第 `c_a` 位为 1 的 one-hot |

### R6. 自举密钥体积（工程成本，不是"缺原语"）

| | |
|---|---|
| **论文依据** | 论文取 `ℓ_rgsw = 8`（Pirouette Table 4）；我们现状 `levels = 25` |
| **现状** | 论文规模下 1 个 RGSW ≈ 50 MB；`d=512` 时 BK ≈ **25.6 GB**（外推），盲旋转 ≈ 352 s |
| **整改** | 用 **RNS / 直接切段**把 `ℓ` 从 25 降到 8 → 每个 RGSW ≈ 16 MB，BK ≈ **8.2 GB**；详见第三节路线 1 |
| **验收** | 同参数下 `describe()` 的 `levels` 降到 8；`RGSW(1)⊗c=c` / `RGSW(0)⊗c=0` / CMUX 三条用例仍全对 |

### R7. 参数表收口（`ℓ_BF`、`R`/`C`、密文字节数）

| | |
|---|---|
| **论文依据** | SETUP 第 4 行 `Select R,C such that RC ≥ L_BFF, R ≤ N`；§5.1 Bloom 参数 |
| **现状** | `R`/`C` **未定值**；`ℓ_BF = N = 16384` 是由"查询定长"反推的；通信量按 **9 素数** 估，实测密文是 **8 素数**（差 12.5%） |
| **整改** | 定下 `R`、`C`、`ℓ_BF` 并写进 `CAPE_参数表.md`；把按 9 素数推出来的字节数**用实测值重算** |
| **验收** | 参数表里每个数字都标注"论文给的 / 反推的 / 实测的"；`SizeProbe` 能量出真实 query/response 字节数 |

### R8. 端到端联调（SETUP → QUERY → ANSWER → DECODE）

| | |
|---|---|
| **论文依据** | 算法 1/2 全流程 |
| **现状** | 四步里所有**密码学原语**都在论文参数下验证过，但**流程没串起来**：客户端 QUERY 与密文侧 DECODE 都缺 |
| **整改** | 按四步顺序串起来；DECODE 侧补 BFF 重构（k=3 分量相加 mod t）+ 指纹校验（40 bit）+ 载荷解析 |
| **验收** | 跑通一次完整检索：命中返回正确值集，**不命中返回 ⊥**（指纹不匹配） |

### R9. 文档一致性

| | |
|---|---|
| **整改** | ①`CAPE_子程序实现对照表.md`：第 4c/4f/14 项"列选择必须密文×密文"的理由改写；第 9 项 `LWEtoRGSW` 由 ❌ 改回 **⏸（仅 C 变体）**；②本 README 第〇~三节为最新基准，**冲突时以本节为准** |
| **验收** | 全仓库搜索 `LWEtoRGSW`，不再出现"CAPE 主流程必需"的表述 |

---

# 三、探索：不需要 `LWEtoRGSW` 的盲旋转（只用 LWE 输入）

## 3.1 先纠正前提：论文的 `BlindRotate` 本来就是"只吃 LWE"

§2.5 原文：

> **`BlindRotate(ct_L, ct_R) → ct'_R`**：Given a **LWE encryption** `ct_L ← LWE.Enc_s(r)` and an RLWE
> encryption of an accumulator `P(X) = Σ p_i X^i`, it homomorphically rotates the accumulator according to
> the encrypted index `r`, such that `p_r` is moved to the designated coefficient of `ct'_R`, which we take
> to be the constant coefficient.

也就是说：**CAPE/FusePIR 的盲旋转，输入就是一条 LWE 密文**（行选择器 `q_row,a = LWE.Enc(r_a)`），
**它根本不经过 `LWEtoRGSW`**。我们要找的"不需要 LWE→RGSW 的盲旋转"，**就是算法 1 里那个 `BlindRotate`**。

## 3.2 为什么它不需要 `LWEtoRGSW`

因为它按**秘密位**分解，而不是按**索引位**：

```
X^{−r} = X^{−β} · X^{⟨a,s⟩} = X^{−β} · Π_i X^{a_i·s_i}
```

- `a_i` 是**公开**的（算法 4 里由种子 ρ 经 PRG 派生，线上只传 ρ 与 β），所以 `X^{a_i}` 是**公开旋转**；
- 只有 `s_i ∈ {0,1}` 需要保密，而 `BK_i = RGSW(s_i)` 是**密钥持有者在 SETUP 阶段生成的公开评估材料**
  （算法 4 SETUP 第 2 行："Generate the **public evaluation material** required by …"）；
- 每轮就是 `ACC ← CMUX(BK_i, ACC, ACC·X^{a_i})`，共 `d` 轮，末尾补一次公开旋转 `X^{−β}`。

**要点：`BK` 是"秘密位的 RGSW"，不是"把查询的比特转成 RGSW"。** 后者（`LWEtoRGSW`）才是
circuit bootstrapping，只有 C 变体才需要。

## 3.3 这个盲旋转我们已经有了，而且实测通过

| 项 | 实测（**本轮亲自跑过**） |
|---|---|
| `BlindRotateOps.blindRotate(m, bk, acc, a, β)`（d 轮口径） | N=2048：`r=777`、`r=31` 两个下标都对，整条累加器 2048/2048 一致 |
| `BlindRotateComplete`（真实载荷 + 加密索引 + SampleExtract + Pack） | **4/4**，常数位 = `payload[r]` |
| 两口径互验 | 口径 1（`⌈log₂N⌉` 轮）与口径 2（d 轮）结果**完全一致** |
| 论文规模单轮成本 | 外部乘积 726 ms / CMUX 688 ms / 公开旋转 ≈0 ms |

**接口签名与论文一致**：`blindRotate(..., long[] a, long beta, ...)` —— 吃的就是 `(a, β)`，即一条 LWE 密文。
**所以这一项不需要新写原语，只需要按论文的调用方式接进 ANSWER。**

## 3.4 真正的成本问题：`d` 个 RGSW

| 口径 | 轮数（N=16384） | 自举密钥 | 盲旋转耗时 | 用在哪 |
|---|---|---|---|---|
| **按秘密位（d 轮）** | **512**（d=512） | **512 个 RGSW** ≈ 25.6 GB | ≈ 352 s（外推） | **CAPE / FusePIR** ← 我们的基准 |
| 按索引位（`⌈log₂N⌉` 轮） | 14 | 14 个 RGSW ≈ 700 MB | 19.9 s（实测） | CAPE-C / FusePIR-C（**需 `LWEtoRGSW`**） |

**CAPE 用上面那一行**：不需要 `LWEtoRGSW`，但密钥大 37 倍。**这是 CAPE 与 CAPE-C 的核心取舍。**
所以"探索"的目标不是"找一个不需要 `LWEtoRGSW` 的盲旋转"（已经有了），而是
**"在不用 `LWEtoRGSW` 的前提下，把自举密钥和轮数压下来"**。

## 3.5 三条可选路线

### 路线 1（推荐，改动最小）：保留 BK，把每个 RGSW 做小 —— RNS / 直接切段

- 现状 `levels=25` 是因为切段数字必须以**明文**喂进 `multiplyPlain`，而明文窗口只有 `±t/2 = ±32768`
  → 逼出 `B ≤ t`、`ℓ = ⌈389/16⌉ = 25`。
- 改用 **RNS/直接切段**（Garner 还原 / SEAL 的 `util::decompose` 同款分解）可对齐 Pirouette 的 `ℓ_rgsw = 8`：

  | 手段 | levels | 每个 RGSW | BK（d=512） |
  |---|---|---|---|
  | 现状（明文切段，B=2¹⁶） | 25 | 50 MB | **25.6 GB** |
  | **RNS/直接切段（ℓ=8）** | **8** | ≈16 MB | **≈8.2 GB** |

- **不改变协议结构**，纯实现优化，**风险最低**；对拍用例现成（`RGSW(1)⊗c=c`、`RGSW(0)⊗c=0`、CMUX 两分支）。

### 路线 2（备选，激进）：彻底去掉 RGSW —— 双 one-hot 选择器 + 重线性化

**想法**：既然**列**选择能用"密文 × 明文"做（选择器作明文系数），**行**选择也能用同一招——
只要客户端把**行**也加密成 one-hot，并把两次选择合成一次乘法：

```
ct_prod ← CtCtMul(ct_col, ct_row)        然后重线性化（规模 3 → 2）
ct_out  ← CtPtMul(ct_prod, P*_b(X))      明文：整张表按 2D 交错打包
ct_L    ← SampleExtract_0(ct_out)        → 目标条目的 LWE 密文
```

**不需要 BK、不需要 RGSW、不需要 512 轮 CMUX。** 服务端侧：

| | 论文口径（d 轮 CMUX） | 路线 2 |
|---|---|---|
| 服务端耗时（外推） | ≈352 s | **≈0.5 s**（346+143 ms 的 CtCtMul + 一次 CtPtMul + SampleExtract） |
| SETUP 评估材料 | 512 个 RGSW ≈ 25.6 GB | **一把重线性化密钥** |
| 查询里行选择器 | 一条 LWE（≈36 B） | **一个 RLWE one-hot（≈1 MB）** |
| 环约束 | `R ≤ N` | **`RC ≤ N`** |

**代价与风险（必须写清楚）：**

1. **它改变了论文的协议步骤**——不再使用论文的 `BlindRotate`。按本项目"**不改变原论文的算法**"的硬约束，
   它**不能作为主线**，只能作**性能对照 / 成本备选**（或作为单独立项的研究记录）。
2. 查询从"3 RLWE + 3 LWE"变成"6 RLWE"，**上传量增加**；方向上与 FusePIR-C 恰好相反
   （C 变体是"查询更小、服务端更贵"，这条是"查询更大、服务端更便宜"）。
3. 需要在负循环环里把**符号约定**（`X^{−k} = −X^{N−k}`）逐位对拍，并用
   `SampleExtract → Pack → 库解密` 的**真实解密**验收（**不能用自证式恒等式验收**）。
4. 安全性论证要重写一遍（选择器整体 one-hot 加密，应仍由 RLWE IND-CPA 覆盖，但不能只靠"看起来可以"）。

### 路线 3（探索性）：混合 / 分层压缩 BK

- 把 `d` 位分块，块内用更小的 gadget 因子，或让 BK 只在 RLWE 层用**更小的模数**（BK 不参与 `q_L` 的旋转群约束），
  以进一步压体积。
- 论文没有给这些优化，**属于工程优化，风险中等，收益不确定**；建议在路线 1 落地后再评估。

### 建议

> **主线走路线 1**（保留 CAPE 的结构与 `BlindRotate`，只把 `ℓ` 从 25 压到 8）。
> **路线 2 单独立项做实验**，成果只用于"性能对照 / 成本备选"，**不要混进主流程**——
> 否则就违反了"不改变原论文的算法"。
> 路线 3 暂缓。

---

# 四、默认使用哪个文件夹（别拿错）

**一句话**：默认路线是**纯 Java**——**库在 `lib/`**，**实现的代码在 `rgsw-lab/` 与 `lwe-java/`**。
三份"看起来都像"的东西里只有一份是默认的，其余是对照或弃用。

| 功能 / 论文子程序 | ✅ **默认用这个文件夹** | 入口（文件 → 方法） | ❌ **不要用** |
|---|---|---|---|
| **RLWE 层**：`RLWE.Enc/Dec`、`CtCtAdd`、**`CtPtMul`**、`CtCtMul`、`CtRotate`、模数切换 | 库 **`lib/`** + 调用代码 **`rgsw-lab/`** | `lib/mpc4j-crypto-fhe-seal.jar`（**已打补丁**）<br>`rgsw-lab/.../Mpc4jRgsw.java`：<br>· `encrypt` / `decrypt`<br>· `add` / `sub` / `scalarMultiply`<br>· **`CtPtMul` = `evaluator.multiplyPlain`**（列选择就用它）<br>· `multiplyPowerOfX` = **`CtRotate`**（系数域）<br>· CtCtMul 用 `m.evaluator.multiply` + `relinearizeInplace`<br>· 旋转/模切换用 `m.evaluator.rotateRowsInplace` / `modSwitchToNextInplace` | ❌ **`rlwe-java/`**（自研，**已弃用**，缺缩放回落）<br>🔵 `native-jni/`（真 SEAL，**仅对照**） |
| **LWE 层**：`LWE.Enc/Dec`、模数切换 | **`lwe-java/`** | `src/main/java/cape/he/LWE.java`：`keyGenBinary` / `encrypt` / `decrypt`<br>`LWECiphertext.switchModulus` | ❌ 没有第二份。MPC4J 全仓库没有 LWE，**别去别处找** |
| **RGSW**：`RGSW.Enc`、外部乘积、`CMUX` | **`rgsw-lab/`** | `Mpc4jRgsw.java`：<br>· `encryptRgswConstant(μ)`（**自举密钥 BK**）<br>· `encryptRgswPoly(m)`（一般多项式，`enc_sk` 用）<br>· `externalProduct(rgsw, ct)`<br>· `cmux(rgsw, a, b)` | ❌ `rgsw-lab/` 里的 `RgswOps.java`、`RgswCiphertext.java`、`MonomialOps.java`、`BootstrapKey.java`、`LabConfig.java`、`RgswLabMain.java`、`MonomialKeyTest.java`、`examples/RlweDemo.java`（**路线 C，已加弃用横幅**） |
| **`BlindRotate`** | **`rgsw-lab/`** | `BlindRotateOps.java`：**`blindRotate`（d 轮 = CAPE 口径 ✅）** / `blindRotateByBits`（逐索引位 = CAPE-C 口径）<br>`BlindRotateComplete.java`（端到端完整版） | ❌ 无替代 |
| **`SampleExtract_j`** / **`Pack`** | **`rgsw-lab/`** | `LweRlweBridge.java`：`sampleExtract` / `packFromSample` / `decryptSampleViaPack` | ❌ 无替代（两者是互逆映射，故意写在同一文件里） |
| **`LWEtoRGSW`** | **⏸ 本次不做** | `LweToRgswOps.java`（骨架，现测不通过）——**仅 CAPE-C 需要** | — |
| **数据库预处理**（明文侧：BFF / Bloom / 载荷 / **列多项式 `P_{c,b}(X)`**） | **`cape-fusepir-database-handoff/`** | `DatabasePreprocessor.java`、`BloomParameters.java`、`PlaintextPayload.java` | — |
| 参数位宽 / 性能测量 | `param-probe/`、`rlwe-bench/`、`rgsw-lab/SizeProbe.java` | — | — |

**为什么 RLWE 的"默认"是两处**：**库**（那个 jar）在 `lib/`，而**调用它的代码**在 `rgsw-lab/`
（`Mpc4jRgsw.java` 就是 RLWE 层的门面）。`rlwe-java/` 是**最早的自研版**，不是默认。

**最容易搞混的六处**：

1. **两个都叫 `lib` 的目录**：`coding/lib/` 是**Java jar**（默认）；`coding/native-jni/lib/` 是**真 SEAL 的 DLL**（仅对照）。
2. **`coding/rlwe-java/` 不是默认的 RLWE**——默认的 RLWE 调用代码在 **`coding/rgsw-lab/`**。
3. **两套 RGSW**：`Mpc4jRgsw.java`（默认）vs `RgswOps.java`（弃用）。
4. **`rgsw-lab/` 里有两个 run 脚本**：`run-mpc4j.ps1`（**默认入口**）vs `run.ps1`（路线 C，顶部有 `LEGACY - ROUTE C ONLY` 警示）。
5. **LWE 只有一份**：`coding/lwe-java/`。
6. **"MPC4J 的 SEAL"有两种形态**：`lib/mpc4j-crypto-fhe-seal.jar` 是**逐类翻译的 Java 重写**；`native-jni/lib/mpc4j-native-fhe.dll` 是**真 SEAL 的 C++ JNI 封装**。两者语义一致，但性能与内存上限不同。

> 库的门面（`Mpc4jRgsw`）同时承载 RLWE 与 RGSW 两个子程序，这是**故意的**：
> RGSW 必须在 RLWE 之上才能写，拆成两个文件会逼出大量重复代码。

---

# 五、四步 ↔ 代码总览

| 步骤 | 论文里做什么 | 对应代码 | 状态 |
|---|---|---|---|
| **SETUP** | 选参数；生成 HE 密钥与**评估材料**（重线性化密钥、旋转密钥、**自举密钥 BK**）；数据库预处理（BFF + Bloom + 载荷编码 + **列多项式打包**） | 明文侧：`cape-fusepir-database-handoff/`<br>密钥材料：`rgsw-lab/`、`lwe-java/` | 🟡 原语齐；**列打包未接**；BK 体积待压 |
| **QUERY** | 哈希 → BFF 位置 → 坐标 `(c_a,r_a)` → **列 one-hot 的 RLWE 加密** + **行 `r_a` 的 LWE 加密**（+ 加密 Bloom 向量） | `lwe-java/`（LWE ✓）<br>`rgsw-lab/`（RLWE ✓） | 🔴 **客户端查询逻辑未实现** |
| **ANSWER** | **`CtPtMul` 列选择** + **`BlindRotate`** + `SampleExtract_0` + 三路相加 + Bloom 打分（`CtCtMul` + `Σ CtRotate(·,2^r)`）+ 响应组装 | `rgsw-lab/` | 🟡 **原语全部实测可用**；流程编排缺 |
| **DECODE** | 解密 + BFF 重构（k=3 相加 mod t）+ 指纹校验（40 bit）+ 载荷解析（+ 阈值 τ 判定） | 明文侧结构 ✓ | 🔴 **密文侧解码未实现** |

**一句话现状**：**四步里所有"密码学原语"都已在论文参数下验证过（N=16384），缺的是把它们按协议串起来的流程**。
按第〇节的基准，**没有"缺某个研究级原语"的硬障碍了**；剩下的是编排工作 + BK 体积这项工程优化。

---

# 六、项目结构

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
| `Mpc4jRgsw.java` | `RLWE.Enc/Dec`、`CtCtAdd`、**`CtPtMul`**、`CtCtMul`、**`CtRotate`**、`RGSW.Enc`（常数与一般多项式）、外部乘积、`CMUX` |
| `Mpc4jCapability.java` | 四项能力探针（打包 / ct×ct+重线性化 / 旋转 / 模数切换） |
| `BlindRotateOps.java` | **`BlindRotate`** 两种口径（**d 轮 = CAPE**；逐索引位 = CAPE-C） |
| `BlindRotateComplete.java` | 完整盲旋转（真实载荷 + 加密索引，端到端 4 项验收） |
| `LweRlweBridge.java` | **`SampleExtract_j`** + **`Pack`**（互逆映射，同一文件） |
| `SizeProbe.java` | 实测真实密文的素数分量数与序列化字节数 |
| `LweToRgswOps.java` | `LWEtoRGSW`（❌ 未通过；**仅 CAPE-C 需要，本次不做**） |
| `RgswPolyTest.java`、`RgswPolyDiag.java` | 一般多项式 RGSW 的验证与诊断 |
| `RgswOps.java` 等 8 个 | ❌ **路线 C 遗留**（自研），已加弃用横幅 |
| `run-mpc4j.ps1` | 默认自检入口（`-Class` 可指定主类） |
| `run.ps1` | ❌ 路线 C 入口（顶部有 `LEGACY` 警示） |

---

# 七、SETUP

**论文要求**（§2.5、算法 1/4/5 SETUP）：选公开参数 `(N,d,t,q)`；生成 `sk=(s_L,s_R)`；
**`Select R, C such that RC ≥ L_BFF, R ≤ N`**；
生成**评估材料**——重线性化密钥、Galois 旋转密钥、**自举密钥 `BK={RGSW(s_i)}`**；
数据库侧构造 BFF（k=3 位置、段长 s、总长 `L_BFF ≈ 1.125n`）、每个值的 Bloom 过滤器、
载荷 `y_K = fp(K) ‖ m_i ‖ v_1 ‖ … ‖ v_m ∈ Z_t^{B_pay}`，
并把数组排成二维后**把每一列打包成一个多项式** `P_{c,b}(X) ← Σ_{r=0}^{R−1} D[r+cR][b]·X^r`。

**已有** ✅

| 项 | 位置 | 实测 |
|---|---|---|
| RLWE 密钥、上下文 | `Mpc4jRgsw` 构造函数 | N=16384 起效，`describe()` 打印声明/工作素数 |
| 重线性化密钥 | MPC4J `createRelinKeys` | 215 ms |
| **旋转密钥** | MPC4J `createStepGaloisKeys` | 118 ms；**论文只需 `{1,2,4,…,ℓ_BF/2}` 共 log₂ℓ_BF = 14 个步长**（由算法推得） |
| **自举密钥** `BK={RGSW(s_i)}` | `encryptRgswConstant` | 是盲旋转的 setup 材料（**CAPE 用它，不需要 `LWEtoRGSW`**） |
| LWE 密钥（二进制） | `lwe-java` `keyGenBinary` | 200/200 |
| 数据库预处理（明文侧） | `cape-fusepir-database-handoff/` | 含测试 |

**缺** ❌

1. **二维列打包接进密文流水线**：`P_{c,b}(X)` 目前只算了行数/列数，**多项式构造没写**（对应整改 R2）；
2. **`R`、`C`、`ℓ_BF` 未定值**（对应整改 R7）；
3. **密钥/材料持久化**：setup 产物落盘、跨进程复用（现在全在内存里）；
4. **BK 体积**：`d=512` 时 25.6 GB（对应整改 R6 / 路线 1）。

---

# 八、QUERY

**论文要求**（算法 1 QUERY，对齐 CAPE 后）：

```
ℓ_c = ⌈log₂C⌉,  ℓ_r = ⌈log₂R⌉
for a = 0..2:
    u_a ← h_a(K),  r_a ← u_a mod R,  c_a ← ⌊u_a / R⌋
    q_col,a ← RLWE.Enc_{s_R}(e_{c_a})      ← one-hot 向量的 RLWE 加密（每一位 = 明文多项式的一个系数）
    q_row,a ← LWE.Enc_{s_L}(r_a)           ← 一条 LWE 密文（不是逐位）
    q_a ← (q_col,a, q_row,a)
q ← (q_0, q_1, q_2)
```

**CAPE 额外**：把 `K_2,…,K_Q` 插进一个 Bloom 过滤器得到 `b_qry`，本地保留 `τ = ‖b_qry‖₁`，
再 `q_BF ← RLWE.Enc_{s_R}(b_qry)`；`q ← (q_anc, q_BF)`。

> **注意**：`LWEtoRGSW`、`ρ` 种子压缩、`bin_{ℓc}(c_a)‖bin_{ℓr}(r_a)` 逐位加密**都属于 C 变体**，
> 本项目的 QUERY **不包含**这些步骤。

**已有** ✅：LWE 加密（含二进制密钥、模数切换、`q_L = 2N` 预设）；RLWE 加密；`Pack` 的单系数版本。

**缺** ❌

1. **坐标拆分 `u_a → (c_a, r_a)`** 与 BFF 位置计算（对应整改 R5）；
2. **列 one-hot 的 RLWE 加密**（把 `e_{c_a}` 摆成多项式系数再加密）；
3. **加密 Bloom 查询的定长构造**（`ℓ_BF` 待定，见 R7）；
4. **查询序列化**（线上格式）。

---

# 九、ANSWER

**论文要求**（算法 1 ANSWER + 算法 2 第 2~7 行）：

```
for a = 0..2:
    for b = 1..B_pay:
        Acc_{a,b}    ← Σ_{c=0}^{C−1} CtPtMul(q_col,a[c], P_{c,b}(X))   ← 列选择：密文 × 明文
        Acc'_{a,b}   ← BlindRotate(q_row,a, Acc_{a,b})                 ← 行选择：LWE 输入
        ct_{a,b}     ← SampleExtract_0(Acc'_{a,b})
for b: ct_pay,b ← ct_{0,b} + ct_{1,b} + ct_{2,b}
resp ← Pack({ct_pay,b})
# CAPE 追加（算法 2）：
for j = 1..m:
    ct_score,j ← CtCtMul(q_BF, ct_j^BF)
    for r = 0..log₂ℓ_BF−1: ct_score,j ← CtCtAdd(ct_score,j, CtRotate(ct_score,j, 2^r))
resp ← ({ct_vj, ct_score,j})_{j=1}^m
```

**已有** ✅（**全部在 N=16384 论文参数下实测**）

| 子程序 | 实测 |
|---|---|
| `CtCtAdd` / **`CtPtMul`** | ✅ |
| **`CtCtMul`**（含重线性化 + BFV 缩放回落） | ✅ 346+143 ms，0/16384 错位 |
| **`CtRotate`** | ✅ 85 ms（另 `rotateRows` 也通过） |
| 模数切换 | ✅ 9→8 素数，噪声 368→316 bit |
| **`RGSW.Enc`**（常数 + 一般多项式） | ✅ `RGSW(1)⊗c=c`、`RGSW(0)⊗c=0`、`RGSW(m)⊗c = m⊛msg` 全 0 错位 |
| 外部乘积 / `CMUX` | ✅ 726 ms / 688 ms |
| **`BlindRotate`**（**d 轮 = CAPE 口径**） | ✅ N=2048 两个下标全对；口径 1 与口径 2 结果一致 |
| **`BlindRotate`** 完整版（真实载荷 + 加密索引） | ✅ **4/4** |
| **`SampleExtract_j`** / **`Pack`** | ✅ 往返 5 个系数 0 错 |
| 噪声余量（ct×ct 后） | ✅ **339 bit**（N=4096 时只有 24 bit） |

**缺** ❌

1. **列选择 `Σ_c CtPtMul(...)` 的编排**（对应整改 R2）——底层算子现成，**这一步没写**；
2. **二维布局（R×C）与列打包**（`P_{c,b}(X)` 的多项式构造，对应整改 R2/R7）；
3. **Bloom 打分编排**（`CtCtMul` + `Σ CtRotate(·,2^r)`，对应整改 R4）；
4. ⚠️ **BK 体积**：d 轮口径需要 `d` 个 RGSW，`d=512` 时约 **25.6 GB**（对应整改 R6 / 第三节路线 1）；
5. ⏸ **`LWEtoRGSW`**：**仅 CAPE-C 需要，本次不做**（第〇节）。

---

# 十、DECODE

**论文要求**：解密候选值密文与分数密文 → **BFF 重构**（把 k=3 个位置的值**分量相加 mod t**）
→ **指纹校验**（fp = 40 bit）→ **载荷解析**（按 `f=⌈m/N⌉`、`ℓ=⌈max|v|/t⌉` 切出 m 个值）
→ 合取时用**本地保留的阈值 τ**（查询 Bloom 的汉明重量）判定候选，**返回 `s_j = τ` 的候选集合**。

**已有** ✅：明文侧的数据结构与解析逻辑（`cape-fusepir-database-handoff/`，含测试）；
客户端可解密（库解密器 + `decryptSampleViaPack`）。

**缺** ❌：密文侧解码流程的编排（解密 → BFF 重构 → 指纹 → 解析）；阈值判定；四步串起来的端到端联调（整改 R8）。

---

# 十一、参数现状

| 参数 | 值 | 来源 |
|---|---|---|
| `t` | 65537 | ✅ 论文 §5.1 |
| `N` | 16384 | ✅ 论文 §5.1 |
| 系数模数 | 声明 9 素数 / 438 位；**工作层 8 素数 / 389 位**（BFV 留最后一个素数作 `q_last`） | 论文只说"SEAL 默认"；位数我们实测补出 |
| BFF `k` / 指纹 / `ε_BF` | 3 / 40 bit / 2⁻²⁰ | ✅ 论文 §5.1 |
| `ℓ_BF` | = N = 16384 | ⚠️ 由"查询恰为 1 个密文"反推（整改 R7 待核） |
| `R`、`C`、`ℓ_c`、`ℓ_r` | `R ≤ N`、`RC ≥ L_BFF`；`ℓ_c=⌈log₂C⌉`、`ℓ_r=⌈log₂R⌉` | ✅ 约束是论文给的；**具体取值未定** |
| **`d`（LWE 维数）** | **512** | ⚠️ **论文没给**，取自 Pirouette Table 4 |
| `q_L` | `2N`（结构约束：盲旋转要求 q 为 2 的幂且 q=2N） | ✅ 推得 |
| `σ²` | 3.192（σ≈1.7866） | ⚠️ Pirouette |
| gadget 底 / 层数 | 现状 2¹⁶ / 25；（Pirouette：`B_rgsw=2²⁴`、`ℓ_rgsw=8`） | ⚠️ 有差距，见整改 R6 |
| 旋转密钥步长集 | `{1,2,4,…,ℓ_BF/2}` = 14 个 | ✅ 由算法推得 |

---

# 十二、所缺东西汇总（按优先级）

| # | 缺什么 | 影响到哪一步 | 难度 | 对应整改 |
|---|---|---|---|---|
| 1 | **列选择 `Σ CtPtMul` + 二维列打包** | SETUP / ANSWER | 中 | R2 |
| 2 | **客户端 QUERY 逻辑**（坐标拆分 + one-hot RLWE 加密） | QUERY | 中 | R5 |
| 3 | **Bloom 打分编排**（`CtCtMul` + `Σ CtRotate`） | ANSWER | 低 | R4 |
| 4 | **密文侧 DECODE 流程 + 阈值判定** | DECODE | 中 | R8 |
| 5 | **BK 体积**（RNS 切段，ℓ 25→8，25.6 GB→8.2 GB） | ANSWER 性能 | 中（算法已读懂） | R6 |
| 6 | **参数收口**（`R`/`C`/`ℓ_BF`、字节数按实测重算） | SETUP / 通信量 | 低 | R7 |
| 7 | 密钥持久化 + 四步端到端联调 | 全部 | 低 | R8 |
| 8 | 与 native 的同参数性能对拍 | — | 低 | — |
| ⏸ | `LWEtoRGSW`（**仅 C 变体**） | — | — | R1（本次不做） |

---

# 十三、跑起来

```powershell
# 默认路线（纯 Java）—— 各项自检
cd coding\rgsw-lab
.\run-mpc4j.ps1                                                  # RGSW + CMUX 自检（5 项）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.Mpc4jCapability 16384    # 论文规模四项能力
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateOps 2048      # 盲旋转两种口径
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.RgswPolyTest 2048        # 一般多项式 RGSW
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.LweRlweBridge 2048       # SampleExtract / Pack
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.BlindRotateComplete 16384 64   # 完整盲旋转（论文规模）
.\run-mpc4j.ps1 -Class com.fusepir.rgsw.SizeProbe                # 量真实密文的素数分量数与序列化字节数

# LWE 层（纯 JDK，无依赖；注意：lwe-java/ 下没有 run.ps1，按 README 手动 javac）
cd coding\lwe-java
# 见 lwe-java/README.md 的 javac 命令

# 对照路线（真 SEAL）
cd coding\native-jni
.\run.ps1 -N 16384
```

> **传参方式**：`-Class` 后面跟的数字会**原样转发**给 Java 程序作为 argv
> （`N`，有的程序还接第二个参数 `d`）。**跑之前先看它打印的 `[params]` 行确认规模生效**——
> 这个转发曾经是坏的（`$args` 没传给 java），导致 `-Class X 16384` **静默按默认规模跑**，
> 现已修复并实测（`LweRlweBridge 4096` → 打印 `N=4096, 3 素数/109 bit`）。

前提：JDK（`D:\Java\jdk` 或 PATH 里的 `javac/java`）。默认路线**不需要任何 C++ 工具链** ✓。

---

# 十四、文档索引

| 文档 | 内容 |
|---|---|
| `默认实现一览.md` | **哪条路线是默认、哪个文件夹放什么**（最容易被搞混的六处） |
| `RLWE路线审计.md` | 三条路线的逐文件判定、补丁带来的转折、论文规模实测结果 |
| `HE_三层调用说明汇总.md` | 三层（LWE / RLWE / RGSW）的关系与 API |
| `rgsw-lab/RGSW_调用说明.md` | RGSW 层的自检与参数；**踩坑记录**（七个坑 + MPC4J 新增的三个） |
| `rgsw-lab/BlindRotate_实测.md` | 盲旋转的论文定义原文、轮数口径修正、论文规模耗时 |
| `rgsw-lab/LWE_RLWE桥_实测.md` | SampleExtract / Pack 实测、方法论警告 |
| `../CAPE_子程序实现对照表.md` | 逐项状态表（**注意：其第 4c/9/14 项正按本 README 第〇、一节整改**） |
| `../CAPE_参数表.md` | 参数总表（论文给的 / 从 Pirouette 继承的 / 我们定的 / 实测的） |
| `../Submission_usenix_232/Submission_usenix_232_精读讲解.md` | 论文精读（算法 1~5 的逐行转写） |
| `SYNC.md` | 推送到远端的步骤与环境问题记录 |
