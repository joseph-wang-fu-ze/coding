# CAPE/FusePIR 数据库模块交接说明

## 已完成

- `MovieLensTagLoader`：读取 `tags.csv`，完成 UTF-8、Unicode NFC、小写、空白规范化。
- `CanonicalDatabase`：提供关键词到 value 的正向关系，以及 value 到关键词集合的反向关系。
- `DatabasePreprocessor`：根据统一的 CAPE 参数生成 Bloom 参数、固定长度明文 payload 和矩阵尺寸。
- `PlaintextDatabasePreprocessor`：密码模块应依赖的最小接口。
- `DatabasePreprocessorTest`：验证多对多关系和 payload 长度一致性。

## 密码模块接口

密码模块可以直接调用：

```java
CanonicalDatabase db = MovieLensTagLoader.load(tagsCsv);
PreparedDatabase prepared = new DatabasePreprocessor().prepare(db, CapeParameters.defaults());
```

然后读取：

- `prepared.payloads()`：关键词到明文 payload；
- `prepared.bloom()`：Bloom 的 `h` 和 `lBF`；
- `prepared.rows()`、`prepared.columns()`：补零后的矩阵布局。

## 当前边界

本模块不实现 RLWE、LWE、BlindRotate、SampleExtract、Pack 或查询协议；也不保存客户端私钥。

当前 `L_BFF` 统计值表示 payload 补零后的矩阵容量。Arithmetic Binary Fuse Filter 的 MappingStep、Encode 和 seed 重试仍需密码/编码模块实现，不能把当前统计值当作论文 Algorithm 3 的最终 BFF 长度。

原始 MovieLens 数据没有打包，队友需要自行下载 `tags.csv` 并传入路径。
