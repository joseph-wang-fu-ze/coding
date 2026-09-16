# 依赖清单（运行必需）

从 `.m2repo` 拷贝而来。坐标 + SHA-256 用于校验与重新获取。

| JAR | SHA-256 | 大小 (MB) |
|---|---|---|
| `slf4j-api-2.0.13.jar` | `e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9` | 0.07 |
| `reload4j-1.2.22.jar` | `222f90d3e69541218ef6e70547749d693bd4c1846817e5bd7949b3e28950f99f` | 0.32 |
| `hamcrest-core-1.3.jar` | `66fdef91e9739348df7a096aa384a5685f4e875584cce89386a7a47251c4d8e9` | 0.04 |
| `guava-32.1.3-jre.jar` | `6d4e2b5a118aab62e6e5e29d185a0224eed82c85c40ac3d33cf04a270c3b3744` | 2.9 |
| `failureaccess-1.0.1.jar` | `a171ee4c734dd2da837e4b16be9df4661afab72a41adaf31eb84dfdaf936ca26` | 0 |
| `bcprov-jdk18on-1.78.1.jar` | `add5915e6acfc6ab5836e1fd8a5e21c6488536a8c1f21f386eeb3bf280b702d7` | 7.94 |
| `trove4j-3.0.3.jar` | `3c8616203d61a12a7e3487e8b34f3c198c2b5ba9e90da0c7ea32d99cd4958012` | 2.41 |
| `commons-lang3-3.9.jar` | `de2e1dcdcf3ef917a8ce858661a06726a9a944f28e33ad7f9e08bea44dc3c230` | 0.48 |
| `commons-math3-3.6.1.jar` | `1e56d7b058d28b65abd256b8458e3885b674c1d588fa43cd7d1cbb9c7ef2b308` | 2.11 |
| `big-math-2.3.2.jar` | `693e1bb7c7f5184b448f03c2a2c0c45d07d8e89e4641fdc31ab0a8057027f43d` | 0.06 |
| `zstd-jni-1.5.5-11.jar` | `d75b2ced6059f81ad23e021c554259b906b6c4f2991cb772409827569ead4c1a` | 6.46 |

## 获取方式

这些都来自 Maven Central，可用任一下载器取：

```
mvn dependency:get -Dartifact=<groupId>:<artifactId>:<version>
```

