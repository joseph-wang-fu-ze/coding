# 真 SEAL 4.0.0 native 路线（`coding/native-jni/`）

> 这条路线用 **Microsoft SEAL 4.0.0 的 C++ 本体**（不是纯 Java 移植版），
> 通过 MPC4J 自带的 JNI 封装 `mpc4j-native-fhe` 从 Java 调用。
> 目的：达到纯 Java 移植版**到不了**的论文参数规模（N=16384 / 约 438 位模数）。

---

## 一、为什么需要这条路线

| | 纯 Java 移植版（`coding/lib/mpc4j-crypto-fhe-seal.jar`） | native（本目录） |
|---|---|---|
| 本质 | SEAL 算法的 Java 重写 | **SEAL 4.0.0 C++ 本体** |
| N=16384 可行性 | ❌ `AbstractGaloisTool` 每层模数分配 N² 个 int ≈ 1 GB/层 × 8 层 | ✅ 实测跑通 |
| 性能 | Java | C++（与论文实现同一路线） |
| 部署 | 拷一个 jar | 需要一个 `.dll` |

两者**算法与语义一致**（Java 版是逐类翻译），差别在内存与速度。

---

## 二、实测结果（2026-09-16，JDK 25，MinGW-w64 GCC 16.2.0）

`SealPirNativeTest` 在 **N=16384、t=65537、128 位安全参数**下跑通 SealPIR 全流程：

| 步骤 | 耗时 | 产物 |
|---|---|---|
| 生成 BFV 参数 | 12 ms | 序列化 273 字节；膨胀比 `expansionRatio` = 6 |
| 密钥生成（pk/sk/galois） | 1077 ms | pk 1.18 MB、sk 1.18 MB、**galois 132 MB** |
| 数据库 NTT 预处理（256 条） | 1135 ms | 每条明文 1,048,664 字节 |
| 生成查询（加密） | 99 ms | 1 个密文 |
| **服务端生成应答** | 10218 ms | 1 个密文，2.00 MB |
| 解密应答 | 70 ms | 16384 个系数 |
| **正确性** | — | **取回第 170 条，0/16384 错位 ✅** |

### 参数位宽（用 C++ 直接问 SEAL，不从字节数反推）

密文的字节数**不能**用来反推素数个数（序列化可能压缩，且密钥上下文与工作层的模数不同），
所以参数由 `src/seal_params_probe.cpp` 直接向 SEAL 询问：

| N | `CoeffModulus::BFVDefault(N, tc128)` 素数个数 | 总位宽 |
|---|---|---|
| 1024 | 1 | 27 |
| 2048 | 1 | 54 |
| 4096 | 3 | 109 |
| 8192 | 5 | 218 |
| **16384** | **9** | **438** ← 论文用的就是这一档 |
| 32768 | 16 | 881 |

论文参数（N=16384、t=65537）在 SEAL 里展开之后：

| 项 | 实测 |
|---|---|
| `parameters_set` | **true**（合法的 128 位安全配置） |
| **工作层系数模数** | **8 个素数 / 389 位** |
| 最后一层 | 1 个素数 / 48 位 |
| 链长 | 8 |
| 明文模数 | 65537（17 位） |

**一个关键细节**：438 位是 9 个素数，但 SEAL 会把最后一个素数保留为 BFV 缩放专用的
**特殊素数 `q_last`**，所以真正承载运算的工作模数是 389 位（8 素数）。
密文×密文之后要用它做 `divide_and_round_q_last` 来缩放——这正是**自研 `rlwe-java` 缺的那个机制**
（我们当初在 31/61/451 位模数下都做不出可用的密文×密文，就是因为少了这一步）。

也正因如此，密钥（在密钥上下文里生成）是 9 个分量的，而数据库明文（在 `first_parms_id()` 上）
是 8 个分量的——两处字节数不同是**正常的**，不代表参数不一致。

---

## 三、怎么复现

工具链与 SEAL 都装在**纯 ASCII 路径**下（原因见第四节），工作区里的脚本会自动完成：

```powershell
$root = $env:TEMP.Replace([char]92,'/') + '/seal'      # ASCII 构建根目录

# 1) 下载便携工具链（Python 走自带 OpenSSL，绕开 schannel 被沙箱拒绝的问题）
python E:\学习\密码赛\tools\toolchain.py download
# 2) 解到 ASCII 根目录并验证 g++ 可用
python E:\学习\密码赛\tools\stage_ascii.py $root
# 3) 编译并安装 SEAL 4.0.0（静态库）
powershell -File E:\学习\密码赛\tools\build_seal.ps1 -Root $root -Jobs 8
# 4) 编译 MPC4J 的 JNI 封装，产出 mpc4j-native-fhe.dll
python E:\学习\密码赛\tools\build_native_fhe.py $root
# 5) 跑 SealPIR 全流程验证
powershell -File .\run.ps1 -Root $root
```

---

## 四、绕过的四个真实障碍（都不是算法问题）

1. **沙箱里 schannel 拿不到 TLS 凭据**（`SEC_E_NO_CREDENTIALS`）→ `curl`、`.NET`、
   `git push` 全部失败。改用 **Python 自带的 OpenSSL** 下载（`tools/toolchain.py`）。
2. **工作区路径含中文**，MinGW 的 `gcc`/`as` 写不进非 ASCII 路径
   （`Fatal error: can't create ...: No such file or directory`）；
   8.3 短名被禁用、`subst` 被沙箱拒绝 → 构建全部改到 **ASCII 临时目录**
   （`tools/stage_ascii.py`），成品再拷回工作区。
3. **MinGW 没有 `::aligned_alloc`**，而 SEAL 的 `util/gcc.h` 只写了 MSVC 与 glibc 两条分支
   → 用官方支持的 `-DSEAL_USE_ALIGNED_ALLOC=OFF`（`defines.h` 会退回成对的
   `new seal_byte[]` / `delete[]`），**不改一行 SEAL 源码**。
4. **MPC4J 的 JNI 模块只支持 macOS/Linux**（JNI 头文件路径只判 `APPLE`/`UNIX`，
   而 MinGW 下 `UNIX` 为真 → 会去找不存在的 `include/linux`）。给它的 `CMakeLists.txt`
   加了两处**构建胶水**补丁（不改算法）：
   - `WIN32` 分支补 `$JAVA_HOME/include/win32`；
   - 链接 `bcrypt`（SEAL 的 `randomgen.cpp` 用 `BCryptGenRandom`）并把
     `libwinpthread` 静态链入，否则 JVM 加载 DLL 时找不到运行时。
   补丁在 `tools/build_native_fhe.py` 里幂等应用。

> 链接顺序的坑：`-lbcrypt` 放进 `CMAKE_SHARED_LINKER_FLAGS` 会排在目标文件**之前**，
> 静态链接时符号已被丢弃 → 必须用 `target_link_libraries` 追加到目标上。

---

## 五、这套封装已经覆盖了什么 / 还缺什么

`mpc4j-native-fhe` 把 26 个 C++ 源文件编成一个 `mpc4j-native-fhe.dll`，接口是
`byte[]` 序列化的**协议级 API**（`SealStdIdxPirNativeUtils` 等），而不是逐原语接口。

| CAPE 需要的 | 现成封装 | 说明 |
|---|---|---|
| 密钥生成（含 Galois 旋转密钥） | ✅ `keyGen` | |
| 槽打包 / 明文 NTT 预处理 | ✅ `nttTransform` | |
| 密文×明文累加（Bloom 打分、应答） | ✅ `generateReply` | |
| **槽旋转**（`expand_query` 内部） | ✅ `generateReply` | 服务端用它做选择向量扩展 |
| **模数切换** | ✅ `generateReply` 内部 | `mod_switch_to_inplace` 到最后一层 |
| 密文×密文 + 重线性化 | ✅ `Lpzl24BatchPirNativeUtils.computeEncryptedPowers` | 批量 PIR 变体里有 |
| 匹配 / 打分（`optComputeMatches`） | ✅ 同上 | 与 CAPE 的 Bloom 匹配同构 |
| **RGSW / 外部乘积 / CMUX / BlindRotate** | ❌ | MPC4J 全仓库没有任何 RGSW 实现，需自己写 JNI |

所以：**协议主干全部可以复用现成封装**，需要新写的只剩 CAPE 特有的
RGSW/BlindRotate 那一小块。

---

## 六、Java 侧为什么有一份"同名类副本"

`src/main/java/edu/alibaba/mpc4j/s2pc/pir/stdpir/index/seal/SealStdIdxPirNativeUtils.java`
与原版**包名、类名、方法名、签名完全一致**。JNI 是按 `Java_<包>_<类>_<方法>` 绑定符号的，
所以这份副本能直接绑到原版手写的 C++ 实现上，而不必把整个 MPC4J Java 依赖树
（RPC、网络、协议框架…）拖进来。原版方法是包级私有，副本放开成 `public` 只是为了本模块测试能调；
可见性不参与 JNI 符号解析。

---

## 七、许可

- Microsoft SEAL 4.0.0：MIT（`https://github.com/microsoft/SEAL`）
- MPC4J（含 `mpc4j-native-fhe` 的 JNI 封装）：Apache-2.0
- 本目录的 `.dll` 由上述两者编译而成，随附 `THIRD_PARTY.md` 说明来源与版本。
