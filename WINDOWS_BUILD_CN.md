# TensorCash Windows 10/11 钱包构建与配置

本仓库包含生成 TensorCash 钱包所需的完整核心源码。Windows 构建目标为
64 位 Windows 10 和 Windows 11。

## 使用 GitHub Actions 构建

1. 打开仓库的 **Actions** 页面。
2. 选择 **Build Windows wallet**。
3. 点击 **Run workflow**。
4. 构建完成后，在该次任务的 **Artifacts** 区域下载：
   - `tensorcash-windows-x64-installer`：可安装的 Qt GUI 客户端钱包；
   - `tensorcash-windows-x64-cli`：`bitcoind.exe`、`bitcoin-cli.exe`、
     `bitcoin-wallet.exe` 等命令行程序。

推送形如 `v*` 的标签时，工作流还会把 Windows 安装程序和 CLI 压缩包附加到
对应的 GitHub Release。

## 在 Ubuntu / WSL 本地构建

源码应放在 WSL 的 Linux 文件系统中（例如 `/root/tensorcash-cli`），不要在
`/mnt/c` 下直接编译。

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build python3 curl git \
  g++-mingw-w64-x86-64-posix nsis zip
git clone https://github.com/kinger2023/tensorcash-cli.git
cd tensorcash-cli
./scripts/build-windows-x64.sh
```

生成文件位于 `dist/windows-x64/`。

## Windows 配置文件

主网默认数据目录：

```text
%LOCALAPPDATA%\TensorCash
```

配置文件路径：

```text
%LOCALAPPDATA%\TensorCash\bitcoin.conf
```

如果以前使用过旧版并且 `%APPDATA%\TensorCash` 已存在，程序会继续使用旧目录。
配置文件不会自动创建，可以复制仓库中的
[`examples/bitcoin.conf`](examples/bitcoin.conf) 后按需修改。

## 推荐基础配置

```ini
chain=tensor
server=1
listen=1
prune=0
```

测试网使用：

```ini
chain=tensor-test
```

主网与测试网不要共用同一个自定义 `datadir`。默认编译的主网程序使用
`TensorCash` 数据目录；通过 `-chain=tensor-test` 运行时会使用对应网络子目录。

## RPC 安全

仅在本机使用 RPC 时保持默认绑定，不要把 RPC 端口暴露到公网。推荐使用 cookie
认证。若必须给局域网程序连接，应使用 `rpcauth`，配置防火墙，并限制
`rpcallowip`；不要在公开仓库提交 RPC 密码。

常用命令：

```powershell
.\bitcoind.exe -daemon
.\bitcoin-cli.exe getblockchaininfo
.\bitcoin-cli.exe getwalletinfo
.\bitcoin-cli.exe stop
```

指定配置或数据目录：

```powershell
.\bitcoind.exe -conf="D:\TensorCash\bitcoin.conf" -datadir="D:\TensorCash\data"
```

## 钱包安全

- 升级或迁移前备份钱包；
- 不要公开助记词、私钥、钱包文件或 RPC 凭据；
- 从 Actions 或 Release 下载后核对 SHA256；
- 自行构建时保留对应的 Git 提交哈希，便于复现和审计。
