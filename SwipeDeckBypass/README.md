# SwipeDeckBypass 1.1.0

独立 Hook 包，配合原版 SwipeDeck 使用，不修改厂商磁盘二进制。

- 在主 dylib 和设置 bundle 代码段中匹配验证函数的指令特征，不写死偏移。
- 只有唯一匹配时安装 Hook；不匹配或多处匹配时停止，不盲改。
- 保留 IsActivated 和 token/cache 初始化，只替换下层签名验证函数。
- 从实际加载路径推导 RootHide/rootless 存储路径，不硬编码 UUID。
- activation.dat 不存在时才创建 64 字节数据，已有文件保持不变。
- 仅在 SpringBoard 与 Preferences 中工作，监听设置 bundle 延迟加载。
- 不再全局 Hook NSData 或 Security.framework。

如果更新仅改变函数位置、调用地址，现有特征可能仍适用；如果改变编译结构、
函数签名或授权流程，需要更新 Hook。不承诺所有未来版本兼容。

先安装原版 SwipeDeck，再安装本 Hook，重启 SpringBoard。
RootHide 使用其转换流程处理 rootless DEB，不直接混装未经转换的包。
破解主包与原版加 Hook 是两种方案，不叠加作为验证依据。

诊断日志位于实际插件存储目录下的 bypass-SwipeDeck.dylib.log 和
bypass-SwipeDeckPrefs.log。它们表示 Hook 安装，不代表全部功能验证通过。

卸载 Hook 后重启 SpringBoard 可恢复原版验证行为，不删除用户配置与授权数据。
1.0.x 的错误路径与宽泛回退方案已经替换，不再交付旧版。
