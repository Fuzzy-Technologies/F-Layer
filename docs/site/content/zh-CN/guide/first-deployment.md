# 首次部署 {#first-deployment}

本指南部署稳定发行版中提供的安全 SSH 网关。需要 Yandex Cloud 账号和已认证的
`yc` 配置档。先运行 `python -m flayer lifecycle --help` 查看可用命令。

部署由明确的堆栈身份、编译后的资源计划、具有所有权的本地状态和有界提供方操作组成。安全网关还包括经过审查的服务器配置档和独立拥有的设备制品。凭据和私钥不得放入计划或文档。

安全制品存储目前要求 POSIX 所有权和权限检查，以及相对于文件描述符的文件系统操作。本操作说明请使用 Linux/macOS；在具备等效 ACL 契约之前，Windows 持久化不受支持。安装和离线诊断是独立能力。

## 操作员步骤 {#operator-sequence}

1. 从所需源代码版本安装，并配置现有 `yc` 配置档。
2. 在本地准备和验证安全网关配置档。
3. 构建服务器制品，检查生成的生命周期计划和 cloud-init。
4. 确认身份、文件夹、SSH 密钥、管理范围和服务端口符合意图。
5. 提供明确的变更许可和精确的文件夹确认后再创建。
6. 查看提供方观测，再单独运行端点诊断。
7. 检查目标范围后，只通过匹配且具有所有权的计划和状态执行销毁。

网关配置档编译是本地操作，不访问云、不生成私钥，也不证明客户机就绪。第一个传输是受限 SSH 本地转发，具有明确目标和逐设备授权。配置档不假定 A-VPN 产品、私有 NAS、固定国家或隐含账户。

## 在本地准备安全网关 {#prepare-a-secure-gateway-locally}

将以下内容保存为操作员控制目录中的 `gateway.toml`。文件夹、区域、镜像、管理地址和公钥均为虚构值，请在部署前替换。选择兼容明确客户机契约的 Ubuntu 24.04 镜像和尽可能小的合适管理 CIDR。

```toml
schema_version = 1
profile = "secure-gateway"
guest_contract = "ubuntu-24.04-cloud-init"

[identity]
project = "example"
stack = "gateway"
provider = "yandex-cloud"
scope_id = "example-folder"
owner_id = "example-owner"

[gateway]
zone_id = "example-zone"
image_id = "example-ubuntu-image"
subnet_cidr = "10.42.0.0/24"
ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"
management_cidrs = ["198.51.100.42/32"]
ssh_username = "gateway-admin"
ssh_port = 22
cores = 2
memory_gib = 2
boot_disk_gib = 20

[transport]
kind = "ssh-local-forward"
username = "gateway-tunnel"

[[transport.targets]]
name = "web"
host = "example.org"
port = 443

[[transport.devices]]
device_id = "laptop"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5"
source_cidrs = ["198.51.100.42/32"]
```

允许 UDP 端口不会安装 VPN。SSH 本地转发使用配置的 SSH 端口；删除未使用的服务项并尽可能缩小范围。生成的客户机配置禁用密码和 root SSH 登录、IPv4 转发和 IPv6，并限制入站访问。它不建立包路由或就绪证据。独立的非 sudo 传输账户只允许声明的本地转发目标和逐设备源 CIDR；管理账户转发保持禁用。

在 POSIX 控制台中本地生成并检查具有所有权的服务器制品包和生命周期计划：

```bash
python - <<'PY'
"""Prepare an owned gateway bundle without accessing a cloud account."""

import os
from pathlib import Path

from flayer.profiles import (
    BuildServerBundle, CompileGateway, LoadGatewayProfile, RenderPlan, WriteArtifactBundle,
)

os.umask(0o077)
profile = LoadGatewayProfile("gateway.toml")
directory = WriteArtifactBundle("generated-artifacts", BuildServerBundle(profile))
plan_text = RenderPlan(
    CompileGateway(profile), user_data_file=directory / "server-cloud-init.json",
)
plan_path = Path("generated-artifacts/plan.toml")

with plan_path.open("x", encoding="utf-8") as stream:
    stream.write(plan_text)

print(plan_path)
PY
```

存储以独占方式发布新制品包，使用严格权限和所有权及哈希清单，从不覆盖现有包。`RenderPlan` 在绑定文件路径前根据配置档验证 cloud-init 字节。产生的本地路径依赖机器；计划和制品包不得进入 Git，编译后也不要移动 cloud-init 文件。

## 生命周期命令契约 {#lifecycle-command-contract}

命令使用相同的明确计划、状态和配置档：

```bash
python -m flayer lifecycle status --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --format json
python -m flayer lifecycle create --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
python -m flayer lifecycle recover --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

`status` 读取提供方观测。`create`、`recover` 和 `destroy` 同时要求 `--allow-mutation` 和与计划作用域 ID 精确相等的 `--scope-confirm`。它们必须使用相同的所有权身份和操作员控制的状态路径。顶层诊断 `status` 与生命周期 `status` 分离。

创建成功证明提供方资源已建立，不证明 cloud-init 已完成或客户端能够连接。选择适合该部署的客户机就绪检查之后，才使用 `health` 检查明确端点。

## 恢复和清理 {#recovery-and-cleanup}

中断操作会在状态文件旁保留日志。超时的创建可能已在远程成功：恢复必须找到精确拥有的逻辑资源，而不是创建副本。无法确定的缺失资源会阻止恢复，等待操作员调查。

进程崩溃可能留下协作式操作锁。手动移除前，请确认旧进程已经终止并检查日志和状态；F-Layer 不会自动擦除可能仍在使用的锁。

回滚只影响该操作创建的资源；操作前已存在且被接纳的精确拥有资源保持不变。显式清理使用：

```bash
python -m flayer lifecycle destroy --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

替换生产值之前，检查真实文件夹和资源身份。删除前，提供方所有权必须匹配。保留日志和状态，直到清理成功且中断结果得到解决。

确认云清理完成后，通过所有权清单移除精确的服务器制品包，不要删除任意目录：

```python
from flayer.profiles import LoadGatewayProfile, RemoveArtifactBundle

profile = LoadGatewayProfile("gateway.toml")
RemoveArtifactBundle(
    "generated-artifacts", profile.identity, kind="server", name=profile.identity.stack,
)
```

## 连接一台已授权设备 {#connect-one-authorized-device}

自行准备与 `transport.devices` 公钥对应的设备私钥。通过可信渠道获取并验证服务器主机密钥，将其放入明确的 `known_hosts` 文件。生成器不读取私钥，也不会将首次观测的服务器密钥视为可信。

实际服务器端点和信任路径已知后，生成设备可用的 SSH 客户端配置：

```python
from flayer.profiles import BuildSshDeviceBundle, LoadGatewayProfile, WriteArtifactBundle

profile = LoadGatewayProfile("gateway.toml")
bundle = BuildSshDeviceBundle(
    profile, "laptop", endpoint="203.0.113.42",
    identity_file="/path/to/laptop-key",
    known_hosts_file="/path/to/trusted-known-hosts",
    local_ports=(8443,),
)
directory = WriteArtifactBundle("generated-artifacts", bundle)
print(directory / "ssh-client.conf")
```

`203.0.113.42` 是文档地址。替换为观测到的端点和自己的明确本地密钥及信任路径；生成路径不可移植。然后保持本地转发运行：

```bash
ssh -F generated-artifacts/device-laptop/ssh-client.conf -N laptop
```

示例将 `127.0.0.1:8443` 绑定到声明的 `example.org:443` 目标。严格主机密钥检查已启用，服务器限制允许的密钥、源范围和目标。本地转发承载选定连接，不是全设备 VPN、包路由器或自动客户端安装。将连接视为成功前，请检查实际 SSH 和端点证据。

设备制品包有独立所有权清单。不再需要时，仅使用 `RemoveArtifactBundle(..., kind="device", name="laptop")` 移除匹配制品包。私钥和可信主机密钥文件仍由操作员单独管理。
