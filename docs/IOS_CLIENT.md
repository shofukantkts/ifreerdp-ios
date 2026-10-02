# iFreeRDP iOS 客户端

这个仓库以 FreeRDP 的 client/iOS 为基础，保留其协议兼容性，同时对 iOS
生命周期、证书信任、密码存储、软件 GDI/Metal 交接和 GitHub Actions 构建做了加固。

## 构建方式

所有 iOS 构建都在 GitHub Actions 的 macos-26 runner 上完成，本地 Linux 不需要
安装 Xcode。公开仓库使用标准 GitHub-hosted runner；模拟器构建不需要签名。

在 public fork 中打开 Actions 后，默认会执行：

- arm64 iOS Simulator 构建；
- 上传 iFreeRDP-simulator.zip artifact；
- Linux 静态检查。

workflow_dispatch 可以开启 full_codecs，让 FreeRDP 的 iOS superbuild 额外编译
FFmpeg H.264/HEVC 路径。默认 CI 关闭可选组件，以减少每次 PR 的构建时间。

## 未签名真机 IPA

如果自己拥有签名方式，不需要把 Apple 证书放进仓库。手动运行 workflow 时，把
`unsigned_device` 设为 `true`；Actions 会构建 `OS64` arm64 真机版本，并上传
`iFreeRDP-unsigned.ipa`。这个包没有 Apple 签名，不能直接点开安装，需要用
AltStore、SideStore、Sideloadly 或自己的 `codesign`/provisioning profile 重新签名。

`device` 选项则是由 GitHub Actions 使用仓库 Secrets 自动签名的完整流程；没有这些
Secrets 时不要选择它。

## 真机签名

真机需要把 workflow 的平台改成 OS64，并配置 Apple Developer 证书与 provisioning
profile。不要把 .p12、.mobileprovision 或密码提交到仓库；它们应放在 GitHub
Secrets，并且签名 job 只允许受保护的手动触发。

构建前可通过 CMake 变量设置自己的 Bundle ID：

    -DIOS_BUNDLE_IDENTIFIER=com.example.ifreerdp
    -DIOS_DISPLAY_NAME=iFreeRDP

## 安全行为

- 证书采用按 host:port + fingerprint 保存的 trust-on-first-use 策略，不再提供
  “接受所有证书”的全局绕过开关。
- 用户确认后的证书指纹存放在 Keychain；设置页的清理按钮同时清理 Keychain 信任和
  FreeRDP 的本地证书缓存。
- 新保存的连接密码使用随机 salt、PBKDF2-HMAC-SHA256、AES-CBC 和
  HMAC-SHA256 的 Encrypt-then-MAC 封装；旧版本密码记录仍可读取，并会在下一次保存
  时升级。主密钥迁移到 Keychain。
- RDP 画面更新和 Metal 上传之间使用互斥锁，避免软件 GDI 缓冲区在渲染时被重用。
- 输入事件管道处理短读/短写、EINTR 和资源关闭，连接进入后台时暂停输出和输入，
  回到前台后恢复。
- 在“适应屏幕”模式下，旋转、iPad 分屏和外接屏尺寸变化通过 Display Control 通道
  请求远端桌面动态调整，不需要重新连接。

## 参考实现

协议核心继续使用 FreeRDP。图形、证书、Keychain、诊断和测试的功能清单参考了
RDPKit 的公开设计，但没有把另一套 RDP 协议实现混入本项目。
