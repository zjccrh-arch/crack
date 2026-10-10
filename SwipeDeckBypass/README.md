# SwipeDeckBypass

这是一个独立的 Theos rootless Hook，不修改厂商 `SwipeDeck.dylib`。正版
SwipeDeck 更新后，只要仍通过 `SecKeyVerifySignature` 完成授权校验，就不依赖
旧版本的函数偏移，不需要重新 patch。

机制：

- 启动时创建 `/var/mobile/Library/Preferences/com.zooah.swipedeck/activation.dat`，
  仅在现有内容不是 64 字节时写入 64 个 Base58 `1`；
- Hook 系统 `SecKeyVerifySignature`，仅当返回地址来自 `SwipeDeck.dylib` 时返回成功；
  其他调用继续执行原函数；
- 通过独立 dylib 注入，不覆盖厂商文件，支持后续正版包直接更新。

## 本地构建

在 macOS + Theos 环境：

```sh
THEOS="$HOME/theos" gmake package FINALPACKAGE=1
```

## GitHub Actions

仓库工作流会在 macOS runner 上安装 Theos 和 iPhoneOS SDK，编译真实 arm64/arm64e
rootless `.deb`，并上传带 SHA-256 的 Actions artifact。

## 安装与回滚

```sh
dpkg -i com.zooah.swipedeck.bypass_1.0.1_iphoneos-arm64.deb
sbreload
```

1.0.1 是设备诊断版，记录初始化、文件写入、SwipeDeck 的 activation.dat 读取路径
以及签名 Hook 命中次数，不记录签名数据、ECID 或任何授权码。
日志位于 `/var/mobile/Library/Preferences/com.zooah.swipedeck/bypass-diagnostic.log`；
RootHide SSH 视图可能需要从 `/rootfs/var/mobile/Library/Preferences/...` 读取。
目前只确认 1.0.0 已注入并执行，设备最终授权状态仍需验证。

```sh
dpkg -r com.zooah.swipedeck.bypass
rm -f /var/mobile/Library/Preferences/com.zooah.swipedeck/activation.dat
sbreload
```
