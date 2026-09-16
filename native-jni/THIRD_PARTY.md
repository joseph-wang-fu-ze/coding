# 第三方组件来源与版本（`coding/native-jni/`）

本目录的 `lib/mpc4j-native-fhe.dll` 由下列两个开源项目编译而成。

## Microsoft SEAL 4.0.0

- 来源：<https://github.com/microsoft/SEAL>，tag `v4.0.0`
- 许可：MIT
- 用途：同态加密本体（BFV），**以静态库 `libseal-4.0.a` 形式链入 DLL**
- 构建方式：见 `coding/native-jni/README.md` 第三节；关键开关
  `-DSEAL_BUILD_DEPS=OFF -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
  -DSEAL_USE_CXX17=ON -DSEAL_USE_ALIGNED_ALLOC=OFF -DBUILD_SHARED_LIBS=OFF`
- 未改动 SEAL 源码

## MPC4J（`mpc4j-native-fhe` 模块）

- 来源：<https://github.com/alibaba-edu/mpc4j>，本地检出 commit `ea3b9aa99389adbe6219b0b909d2cc39cacad2bd`（v1.1.5）
- 许可：Apache-2.0（许可证原文见 `coding/lib/MPC4J-LICENSE`）
- 用途：JNI 封装层（`pir/`、`upso/`、`tfhe/` 等 26 个 C++ 源文件），
  提供 `keyGen` / `generateQuery` / `generateReply` / `decryptReply` 等协议级接口
- 改动：**仅两处构建胶水补丁**（不改算法逻辑），由 `tools/build_native_fhe.py` 幂等应用：
  1. `CMakeLists.txt` 增加 `WIN32` 分支，补 `$JAVA_HOME/include/win32`（上游只判 `APPLE`/`UNIX`，
     而 MinGW 下 `UNIX` 为真，会去找不存在的 `include/linux`）；
  2. 目标追加 `bcrypt` 与静态 `winpthread`（SEAL 的 `randomgen.cpp` 用 `BCryptGenRandom`；
     `libwinpthread` 若动态链接，JVM 加载 DLL 时找不到运行时）。

## 工具链（不随仓库分发，仅记录版本）

| 组件 | 版本 | 说明 |
|---|---|---|
| MinGW-w64 GCC | 16.2.0（ucrt, posix-seh, winlibs r1） | 可执行文件哈希见 `tools/plan.json` 与下载时校验的 `.sha256` |
| CMake | 3.31.6（windows-x86_64 便携版） | 钉在 3.x，因为 SEAL 4.0.0 早于 CMake 4 |
| JDK | 25 | 提供 `jni.h` / `win32/jni_md.h` |

下载与校验：`python tools/toolchain.py download`（winlibs 的 `.sha256` 会强制校验）。
