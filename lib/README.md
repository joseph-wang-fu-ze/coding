# coding/lib —— MPC4J / SEAL（Java 版）打包

> **用途**：把 MPC4J 的 SEAL 纯 Java 模块及其运行依赖打包进 `coding/`，
> 让 `coding/` 内的代码**不依赖工作区之外的任何路径**，拿到就能编译运行。
>
> 打包日：2026-09-16

---

## 一、里面是什么

| 文件 | 大小 | 说明 |
|---|---|---|
| `mpc4j-crypto-fhe-seal.jar` | **0.20 MB** | MPC4J 的 **SEAL 纯 Java 移植**（BFV/CKKS），由 77 个源文件编译而成 |
| `deps/`（11 个 jar） | **22.79 MB** | 运行必需的第三方依赖 |
| `MPC4J-LICENSE` | 11 KB | 上游 **Apache-2.0** 许可证原文（合规要求，勿删） |
| `build.ps1` | — | 一键重建（从 `mpc4j/` 源码重新编译 + 拷依赖） |
| `deps/VERSIONS.md` | — | 各依赖的 Maven 坐标与 SHA-256 |

**来源**：

| 项 | 值 |
|---|---|
| 上游仓库 | `https://github.com/alibaba-edu/mpc4j` |
| 版本 | **v1.1.5**，commit `ea3b9aa99389adbe6219b0b909d2cc39cacad2bd`（2026-04-02） |
| 模块 | `mpc4j-crypto-fhe/mpc4j-crypto-fhe-seal` |
| 许可证 | **Apache License 2.0**（可自由再分发，需保留 LICENSE） |

> ⚠️ **注意"SEAL"指哪个**：这里打的是 **SEAL 的纯 Java 移植**（在 MPC4J 里）。
> 微软官方的 **SEAL C++** 不在本工作区，`mpc4j-native-fhe` 需要它才能编译——
> 我们不走 native 路线（结论见 `CAPE_子程序实现对照表.md` 第四节）。

---

## 二、怎么用

```powershell
cd E:\学习\密码赛\coding\rgsw-lab
.\run-mpc4j.ps1            # 编译并运行架在 MPC4J 上的 RGSW 自检
```

手工方式（相对路径全部落在 `coding/` 内）：

```powershell
$lib = "E:\学习\密码赛\coding\lib"
$cp  = "$lib\mpc4j-crypto-fhe-seal.jar;" +
       ((Get-ChildItem "$lib\deps" -Filter *.jar | ForEach-Object { $_.FullName }) -join ';')
javac -encoding UTF-8 -cp $cp -d out src\main\java\com\fusepir\rgsw\Mpc4jRgsw.java
java -Xmx4g -cp "out;$cp" com.fusepir.rgsw.Mpc4jRgsw
```

---

## 三、怎么重建

```powershell
cd E:\学习\密码赛\coding\lib
.\build.ps1                 # 从 ..\..\mpc4j 的源码重新编译并打包
```

`build.ps1` 做两件事：
1. 用 `javac` 编译 `mpc4j/mpc4j-crypto-fhe/mpc4j-crypto-fhe-seal/src/main/java` 下的 77 个源文件 → `mpc4j-crypto-fhe-seal.jar`；
2. 从 `.m2repo` 拷贝 11 个依赖 jar（若该目录不存在，脚本会提示去 Maven 取，坐标见 `deps/VERSIONS.md`）。

> **为什么要自己编译而不是直接用 Maven 产物**：实测 `Maven 3.9.9 + JDK 25 + source17` 会编译失败
> （"源版本 17 在 --enable-preview 生效时不可用"），所以一直绕开 Maven 直接用 `javac`——
> 详见 `Windows_测试报告.md`。

---

## 四、关于版本库体积（重要）

| 内容 | 是否提交进 git | 理由 |
|---|---|---|
| `mpc4j-crypto-fhe-seal.jar`（0.2 MB） | ✅ 提交 | MPC4J 自己的代码，体积小，是本项目直接依赖 |
| `MPC4J-LICENSE` | ✅ 提交 | Apache-2.0 要求保留 |
| `deps/*.jar`（22.79 MB） | ✅ **默认提交**（`.gitignore` 里做了例外） | 让仓库自包含，目标机器无需联网/Maven |

其中依赖的 22.79 MB 主要来自两个大件：`bcprov-jdk18on`（7.94 MB）与 `zstd-jni`（6.46 MB）。

**若想给仓库瘦身**：把 `deps/*.jar` 加回 `.gitignore`，接收方用 `build.ps1` 从 Maven 拉取
（坐标与 SHA-256 见 `deps/VERSIONS.md`）。是否值得，取决于"目标机器能不能联网"——
比赛/答辩机器常常不能，所以默认选择自包含。

---

## 五、已知的 MPC4J API 坑（实测记录，省得再踩）

用这个库写 RGSW 时踩到的 5 个坑，全部实测：

| # | 现象 | 原因 / 对策 |
|---|---|---|
| 1 | 构造参数报"not compliant with HomomorphicEncryption.org security standard" | `CoeffModulus.create(n, bits)` 会被 128-bit 安全标准拒绝；改用 `CoeffModulus.bfvDefault(n)` |
| 2 | NTT 形式对不上 | **密文形式跟着明文走**：`encryptSymmetric` 的结果形式取决于传入 `Plaintext` 是否 NTT 形式 |
| 3 | `multiplyPlain` 报 "NTT form mismatch" | 明文与密文必须**同形式**，数字明文要先 `transformToNttInplace(pt, ct.parmsId())` |
| 4 | BFV `decrypt` 报 "encrypted cannot be in NTT form" | 解密要求密文在**系数域**，先 `transformFromNttInplace` |
| 5 | `add` 报 "NTT form mismatch" | 两个密文必须同形式（累加器要显式统一到 NTT 域） |

还有一条内存约束：**`SealContext` 在 N=16384 + 9 素数下会 OOM**
（`AbstractGaloisTool` 每层模数分配 N² 个整数 ≈ 1 GB/层）。
实测 N=16384 时 **2~4 个素数可以**，9 个不行。所以本仓库里用 MPC4J 时把模数规模控制在 4 素数以内。
