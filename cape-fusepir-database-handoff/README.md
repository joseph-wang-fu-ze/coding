# CAPE/FusePIR 数据库初始化

首阶段只包含明文数据库初始化，不实现或修改 RLWE/LWE 协议逻辑。

## 导入 Eclipse

`File -> Import -> General -> Existing Projects into Workspace`，选择本目录 `E:\pir`。

输入 MovieLens 的 `tags.csv` 后运行：

```text
com.fusepir.database.DatabaseInitializerMain E:\data\ml-25m\tags.csv
```

输出包括关键词数、值数、最大关联数、Bloom 参数、payload 长度和矩阵布局。原始 MovieLens 数据不放入本项目。
