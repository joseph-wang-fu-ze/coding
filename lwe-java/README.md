# CAPE —— LWE 层(Java 实现)

CAPE 论文同态加密部分的地基:**LWE 加密/解密**。

这一层的定位是团队的"体温计"——后面 `BlindRotate` / `SampleExtract` 写完之后,
都靠它来验证正确性。

---

## 一、如何运行

需要 JDK 11+(本机验证环境:OpenJDK 24.0.2)。

### 先搞清楚:入口在哪个文件

Java 没有"程序入口文件"的概念,**一个程序可以有多个 `main()`**,运行时指定跑哪个类。

本项目的 `main()` **全在 `src/test/java/` 下**,不在 `src/main/java/`:

```
src/main/java/cape/he/     ← 类库(5 个文件,都没有 main)
    LWE.java  LWEParams.java  ModMath.java  LWECiphertext.java  LWESecretKey.java

src/test/java/cape/he/     ← 可执行入口(3 个文件,都有 main)
    LWESelfTest.java   ← 主自检(第 26 行 main)
    NoiseDiag.java     ← 噪声诊断(第 15 行)
    UniformCheck.java  ← 采样器检查(第 8 行)
```

> **常见误解**:`src/main/java` 里的 "main" **不是指 `main()` 方法**,
> 而是 Maven 的目录约定 —— "主源码集",相对 `src/test/java`(测试源码集)而言。
> 所以 `src/main/java` 下本来就没有 `main`。

运行方式:`java -cp <classpath> <全限定类名>`

```bash
java -cp out cape.he.LWESelfTest     # 跑主自检
java -cp out cape.he.NoiseDiag       # 跑噪声诊断
```

---

### 方式 A:命令行

**Windows PowerShell**(注意 PowerShell 不展开 `*.java` 通配符,要显式列文件):

```powershell
cd lwe-java
New-Item -ItemType Directory -Force -Path out | Out-Null

$sources = @()
$sources += (Get-ChildItem "src\main\java\cape\he" -Filter *.java).FullName
$sources += (Get-ChildItem "src\test\java\cape\he" -Filter *.java).FullName
# 必须无 BOM,否则 javac 报 "无效文件名"
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines("sources.txt", $sources, $enc)

javac -encoding UTF-8 -d out "@sources.txt"
java -cp out cape.he.LWESelfTest
```

**Linux / macOS / Git Bash**(bash 会展开通配符,所以更短):

```bash
cd lwe-java
mkdir -p out
javac -encoding UTF-8 -d out src/main/java/cape/he/*.java src/test/java/cape/he/*.java
java -cp out cape.he.LWESelfTest
```

> `@sources.txt` 是 javac 的语法:从文件里读参数列表。
> 因为 PowerShell 不像 bash 那样展开 `*.java`,直接把通配符传给 javac 会失败。

### 方式 B:IntelliJ IDEA(推荐,避开上面所有坑)

社区版免费。打开 `lwe-java` 目录后:

1. 右键 `src/main/java` → Mark Directory as → **Sources Root**
2. 右键 `src/test/java` → Mark Directory as → **Sources Root**
3. 打开 `LWESelfTest.java`,`main()` 左侧会出现绿色三角,点击即可运行

### 其他可运行程序

| 类 | 用途 |
|---|---|
| `cape.he.LWESelfTest` | 主自检,7 项检查,全部应通过 |
| `cape.he.NoiseDiag` | 诊断:实测相位噪声,用于验证噪声模型 |
| `cape.he.UniformCheck` | 诊断:确认均匀采样与 `<a,s>` 正常工作 |

---

## 二、文件说明

```
src/main/java/cape/he/
├── LWEParams.java       参数配置(含参数合法性校验)
├── ModMath.java         模运算工具(所有方法保证返回 [0,q))
├── LWECiphertext.java   密文 (a, b)
├── LWESecretKey.java    三值密钥 s ∈ {0,1,2}^d
└── LWE.java             加解密主体

src/test/java/cape/he/
├── LWESelfTest.java     自检(无需 JUnit)
├── NoiseDiag.java       噪声诊断
└── UniformCheck.java    采样器检查
```

---

## 三、数学约定

```
密钥:   s ∈ Z_q^d          (本实现用三值 {0,1,2})
密文:   (a, b)
        a ← Z_q^d          均匀随机
        b = <a,s> + Delta*m + e  (mod q)
        Delta = floor(q/t)     缩放因子
        e ← 离散高斯,标准差 sigma

解密:   phase = b - <a,s> (mod q)
        把 phase 中心化到 (-q/2, q/2]
        四舍五入到最近的 Delta 倍数,再除以 Delta 得 m
```

---

## 四、两个必须知道的事实

### 事实 1:相位噪声 = e,**不随维度 d 放大**

这是我实现过程中实测纠正的一个常见误解:

```
phase = b - <a,s>
      = ( <a,s> + Delta*m + e ) - <a,s>
      = Delta*m + e                    ← <a,s> 精确抵消
```

构造 `b` 和解密用的是**同一个 a**,所以 `<a,s>` 完全消掉。
**相位噪声就是 e 本身。**

> `sigma * sqrt(d)` 那类放大只在别的场景成立(例如 a 向量本身带误差、
> 或秘密被复用出偏差)。本方案不适用 —— 实测确认:观测噪声标准差
> 与 sigma 精确相等,且不随 d 变化。

**推论**:d 的选择只影响性能和安全性,**不影响解密失败率**。
失败率只取决于 `e` 的大小与预算 `Delta/2 = q/(2t)` 的关系。

### 事实 2:q 必须是 2 的幂,且 **q = 2N**(盲旋转的硬性要求)

不是随便选的安全参数,而是**结构性约束**。

Pirouette 论文 §3.2 明确写了:

> *"we consider input LWE ciphertexts with **modulus q = 2N**"*

**为什么**:盲旋转要把 `b` 编码成 `X^{-b}` 写进累加器,累加器长度是 `2N`,索引按 `mod 2N` 取。只有 `q = 2N` 时,"模 q 的加法群"才能**同构**地嵌入"模 2N 的旋转群"。若 q 是任意素数或不等于 2N,这个映射会断裂。

**这条约束把 q 和 N 绑死了** —— 它们不独立:

```
N = 2^11 = 2048   →   q = 2N = 2^12 = 4096   ✓ (Pirouette Table 4)
N = 2^14 = 16384  →   q = 2N = 2^15 = 32768
```

`LWEParams` 提供了校验方法:

```java
params.satisfiesBlindRotateConstraint(2048)   // N = 2^11 时返回 true
```

---

## 五、参数来源:Pirouette 论文 Table 4

`LWEParams` 的默认值现在取自 **Pirouette 论文(PoPETs 2026)Table 4** ——
也就是 `https://github.com/KULeuven-COSIC/Pirouette` 的实现参数。

### 采纳的值

| 参数 | 值 | 来源 |
|---|---|---|
| `dimension` (n) | **512** | Table 4 |
| `modulus` (q) | **2^12 = 4096** | Table 4(`log2(q) = 12`) |
| `sigma` | **√3.192 ≈ 1.7866** | Table 4(`sigma^2 = 3.192`) |
| `plaintextModulus` (t) | **16** | ⚠️ **Pirouette 未给出**,推断值 |

`t = 16` 的推断依据:`Delta = 4096/16 = 256`,预算 `Delta/2 = 128`,
而 `6*sigma ≈ 10.7`,余量比 ≈ 0.084,很宽裕(实测 0/1000 失败)。

### 完整参数表(供实现盲旋转时参考)

**Table 3 — 比特分解(bit-decomposition)**

| n_in | n_out | N | log2(q_in) | log2(q_out) | log2(Q) | log2(Q_ksk) | B | B_ksk | sigma^2 |
|---|---|---|---|---|---|---|---|---|---|
| 1300 | 600 | 2^11 | 32 | 12 | 56 | 42 | 2^14 | 2^3 | 3.192 |

**Table 4 — 方案切换 + Phase 1-3(本项目采用这一行)**

| n | N | log2(q) | log2(Q) | B | B_rgsw | l_rgsw | sigma^2 |
|---|---|---|---|---|---|---|---|
| 512 | 2^11 | 12 | 56 | 2^8 | 2^4 | 8 | 3.192 |

> 论文注:Phase 1 期间会模数切换到 `Q = 268496897 · 268460033` 以利用 CRT,
> 减少模加/模乘次数。

**Table 5 — 响应维度**

| N_1 | Q_1 | nu_1 | nu_2 | nu_3 |
|---|---|---|---|---|
| 512 | 2^20 | 11 | {7, 9, 12} | 2 |

### 两套 LWE 参数,别搞混

论文 §1.1 说 *"uses a 25-bit plaintext modulus and 32-bit ciphertext modulus for LWE"*,
而 Table 4 说 `log2(q) = 12`。两者不矛盾,是**不同阶段**:

| 阶段 | 模数 | 明文模数 | 出处 |
|---|---|---|---|
| 客户端**查询** (fresh LWE) | 2^32 | 25 bit | §1.1 / Table 3 的 `log2(q_in)` |
| **盲旋转 / 计算**阶段 | 2^12 | 小 | Table 4 的 `log2(q)` |

**本项目用后者**(q = 2^12),因为盲旋转要求 `q = 2N`。

### ⚠️ 与其他论文的关系

| 论文 | LWE 维度 | 模数 q | sigma | 明文模数 |
|---|---|---|---|---|
| **Pirouette**(已采纳) | 512 | 2^12 | √3.192 ≈ 1.787 | 未给出 |
| CAPE(你们要实现的目标) | 未给出 | 未给出 | 未给出 | 未给出 |
| UKS 2025 / `cppir/ks` | 1024 | 2^32 | 6.4 | 256 |
| ChalametPIR (CCS'24) | 1774 | 2^32 | — | — |

**注意符号冲突**:UKS 那篇的 `N` 指的是 **LWE 维度**(2^10),
而 Pirouette / CAPE 的 `N` 指的是 **RLWE 环维度**(2^11 / 16384)。
同一个字母,两个意思。

**还有一个待确认的冲突**:CAPE 的 RLWE 用 `N = 16384`,而 Pirouette 用 `N = 2^11 = 2048`。
由于 `q = 2N`,如果沿用 CAPE 的 N,则 LWE 的 q 必须变成 `2^15 = 32768`。
**这一点需要和老师确认 —— 到底以哪套为准。**

---

## 六、当前能验证什么 / 不能验证什么

**已通过(9/9)**:

```
### STAGE 0: EXACT MODE (sigma = 0) ###        ← 老师建议的策略
  [PASS] 1000/1000 decryptions correct
  [PASS] q = 4096, 2N = 4096 (N = 2^11)         ← 结构约束满足

### STAGE 1: REAL PARAMS (Pirouette Table 4) ###
  [PASS] q 是 2 的幂 / Delta 非零 / 噪声预算充足
  [PASS] 1000/1000 decryptions correct
  [PASS] 明文 0..15 全部正确
  [PASS] 噪声标准差实测 1.808(设定 1.787)
  [PASS] 参数扫描:失败模式与理论一致
```

**尚未包含(后续要补)**:

- 模数切换 q = 2^12 → Q(Table 4 的 56-bit) — 目前只有雏形,未测试
- 密钥切换
- 与 RLWE 层的接口对接
- **`BlindRotate` / `SampleExtract`**(下一阶段)

---

## 七、`sigma = 0` 模式的用法

老师建议的调试策略,已实现为 `LWEParams.exactlyNoiseless()`:

```java
LWEParams exact = LWEParams.exactlyNoiseless();   // sigma = 0
```

**为什么有用**:噪声为 0 时解密在数学上精确,**任何错误都必然来自逻辑 bug**
(下标错、域搞混、模数切换错),而不是噪声预算不足。把两类问题分离开。

**⚠️ 限制**:

- `sigma = 0` **只用于验证逻辑,不代表任何安全性**
- **盲旋转层自身会引入噪声**(旋转过程的累积误差),那部分不受此参数控制
- 所以 `sigma = 0` 能验证逻辑对不对,**验证不了噪声预算够不够**

### 建议的分阶段调试计划

```
阶段 0  sigma = 0                   ← 已实现,通过
阶段 1  sigma = sqrt(3.192)         ← 已实现,通过(Table 4 真实值)
阶段 2  盲旋转也加噪声,输入 sigma=0  ← 单独测自举噪声,最有价值
阶段 3  全噪声                       ← 最终评测
```

**阶段 2 是关键**:把"输入噪声"和"自举噪声"两个来源分开,才能知道自举吃掉了多少预算。
```

---

## 八、给下一步的接口

`SampleExtract` 输出的是一个 `(A, B)` 形式的 LWE 密文(维度 = 环维度 N)。
验证它时,直接用:

```java
long phase = lwe.phase(sk, A, B);       // b - <a,s> mod q
long m     = lwe.decode(phase);          // 取回明文
```

`phase` 和 `decode` 都做了重载,就是为了让上层直接验证盲旋转的结果,
不必先构造 `LWECiphertext` 对象。

`LWEParams.satisfiesBlindRotateConstraint(N)` 用来在接入盲旋转前
校验 `q = 2N` 是否成立。
