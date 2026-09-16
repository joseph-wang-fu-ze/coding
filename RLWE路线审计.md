# `coding/` 的 RLWE 路线审计

> 目标（用户要求）：**确保 `coding/` 里所有 RLWE 都走 `mpc4j-native-fhe` 路线**。
> 审计时间：2026-09-16。判定标准：**以文件里真正 `import` 的 HE 类为准**（不看注释、不看正则巧合）。

---

## 一、三条路线

| 路线 | 依赖 | 是否目标路线 |
|---|---|---|
| **A. native** | `edu.alibaba.mpc4j.*NativeUtils` → `coding/native-jni/lib/mpc4j-native-fhe.dll` → **真 SEAL 4.0.0 C++** | ✅ **是** |
| **B. 纯 Java 移植版** | `edu.alibaba.mpc4j.crypto.fhe.seal.*` → `coding/lib/mpc4j-crypto-fhe-seal.jar`（SEAL 的 Java 重写） | ❌ 否 |
| **C. 自研** | `com.fusepir.rlwe.*` → `coding/rlwe-java/`（自己写的 RLWE） | ❌ 否（已弃用） |

LWE 不在本次范围：`com.fusepir` 的 `cape.he.*`（`coding/lwe-java/`）是自研 LWE，
**MPC4J 全仓库没有 LWE 实现**，且 LWE 不是 RLWE，保留。

---

## 二、逐文件判定（依据 import）

### ✅ 路线 A（native）——已达标

| 文件 | 说明 |
|---|---|
| `native-jni/.../SealStdIdxPirNativeUtils.java` | JNI 声明副本（绑定到原版 C++） |
| `native-jni/.../Lpzl24BatchPirNativeUtils.java` | 同上（批量 PIR 族） |
| `native-jni/.../SealPirNativeTest.java` | N=16384 全流程验证，已通过 |
| `native-jni/.../NativeApiProbe.java` | 自定义系数模数探针，已通过 |

### ❌ 路线 B（纯 Java 移植版）——待迁移

| 文件 | 内容 | 迁移难度 |
|---|---|---|
| `rgsw-lab/.../Mpc4jRgsw.java` | **RGSW 加密 / 外部乘积 / CMUX**（测试全绿） | 需要 native 侧新增原语接口 |
| `rgsw-lab/.../Mpc4jCapability.java` | 四项能力探针（打包/ct×ct/旋转/模切换） | 同上 |
| `param-probe/.../ParamProbe.java` | 参数位宽探测（N=16384 跑不动，正是它的结论来源） | 可由 `native-jni/src/seal_params_probe.cpp` 替代 ✅ 已有替代品 |
| `rlwe-bench/src/RlweBench.java` | 自研 vs 纯 Java 移植版的性能对照 | 对照基准，可保留但需标注 |

### ❌ 路线 C（自研，已弃用）——待收敛

`rlwe-java/**`（12 个文件，模块本体，已有 `@deprecated` 与 README 警告）
及其消费者：`rgsw-lab/` 的 `RgswOps`、`RgswCiphertext`、`MonomialOps`、`BootstrapKey`、
`RgswLabMain`、`MonomialKeyTest`、`LabConfig`、`examples/RlweDemo`，以及 `rlwe-bench`。

### ⚪ 不含 HE

`cape-fusepir-database-handoff/**`（11 个文件：Bloom 参数、数据库规范化、MovieLens 载入）
—— 纯明文逻辑，与路线无关。

---

## 三、为什么不能"改个 import"就搬过去

`mpc4j-native-fhe` 暴露的是 **byte[] 序列化的协议级接口**（`keyGen` / `generateQuery` /
`generateReply` / `decryptReply` / `computeEncryptedPowers` / `optComputeMatches` …），
**没有原语级接口**，更没有 RGSW：

| 路线 B/C 用到的能力 | native 侧现状 |
|---|---|
| 上下文/密钥、打包、加解密 | 有（藏在协议接口内部） |
| 密文×密文 + 重线性化 | 有（`computeEncryptedPowers` / `optComputeMatches`，需 relinKeys） |
| 槽旋转、模数切换 | 有（`generateReply` 内部用） |
| **单步原语调用**（想按需组合） | ❌ 没有暴露 |
| **RGSW.Enc / 外部乘积 / CMUX / BlindRotate** | ❌ **MPC4J 全仓库没有任何 RGSW 实现** |

所以要让 RGSW 也走 native，**必须给同一个 DLL 增加一层原语级 JNI**
（新写一个 C++ 源文件加进 `mpc4j-native-fhe` 目标，仍然链接同一个 SEAL 静态库）。
这是唯一不改论文算法的办法——换成"用 native 现成的 PIR 接口代替 RGSW"会**改变协议步骤**，
违反"不能改变原论文的算法"。

---

## 四、迁移计划

1. **给 `mpc4j-native-fhe` 增加原语级 JNI**（新文件 `native-jni/src/cape_rlwe_jni.cpp`，
   加进 `tools/build_native_fhe.py` 的编译目标）：
   - 上下文：`ctxCreate(N, t, coeffModBits[])`、`ctxDescribe`（素数个数/位宽/链长）
   - 密钥：`skGen` / `relinKeysGen` / `galoisKeysGen(steps)`
   - 打包：`encode` / `decode`（BatchEncoder）
   - 加解密：`encryptSymmetric` / `encryptZero` / `decrypt` / `noiseBudget`
   - 运算：`ctAdd` / `ctSub` / **`ctMultiply`（含重线性化）** / **`rotateRows`** / **`modSwitchToNext`**
   - **RGSW**：`rgswEncryptConstant` / `externalProduct` / `cmux`
   - 序列化：`ctSave` / `ctLoad`、`ctSize`
2. 把 `Mpc4jRgsw` / `Mpc4jCapability` 的测试**原样搬到 native 版本**上跑（N=16384）。
3. 路线 C 的模块只保留为"交叉校验工具"，并在脚本里加红线（不再作为任何流水线的默认路径）。

### 一个需要定下的实现细节（RGSW 切段）

外部乘积需要把 `src` 的系数按底 B 切成平衡位。q 的工作模数约 389 位，切段需要
**跨 RNS 素数的 CRT 还原**，也就是大整数运算。三个选项：

| 选项 | 做法 | 取舍 |
|---|---|---|
| **a. C++ 侧实现定点大整数** | Garner 算法 + 多字乘加（约 80 行） | 全程 native，但要自己保证正确性 |
| **b. 用 SEAL 内部 RNS gadget** | `util::decompose` + key-switch 同款分解，无需大整数 | 最"native"，但必须吃准它的数学约定 |
| **c. 切段留 Java** | JNI 导出/导入系数（`long[]`），复用已完成并自测的 Java `decompose` | 最快落地；RLWE 运算体仍是 native，但分解在 Java |

倾向 **a 或 b**（满足"全 native"的字面要求），**c** 作为保底快速验证手段。
