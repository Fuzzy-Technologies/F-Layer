# 首次部署 {#first-deployment}

本指南部署稳定发行版中提供的安全 SSH 网关。需要 Yandex Cloud 账号和已完成身份验证的
`yc` 命名配置（profile）。先运行 `python -m flayer lifecycle --help` 查看可用命令。

部署需要指定项目和资源归属、生成资源计划，并保存本地状态，以便按计划创建和管理云资源。安全网关还包括经过审查的服务器配置方案和分别记录归属的设备配置文件。凭据和私钥不得放入计划或文档。

安全制品存储目前要求 POSIX 文件属主和访问权限检查，以及相对于文件描述符的文件系统操作。本操作说明请使用 Linux/macOS；在实现等效的 ACL 权限保障之前，不支持在 Windows 上持久保存这些制品。安装和离线诊断是独立能力。

## 操作员步骤 {#operator-sequence}

1. [安装软件包](installation.md)，并配置现有的 `yc` 命名配置。
2. 在本地准备和验证安全网关配置方案。
3. 构建服务器制品，检查生成的生命周期计划和 cloud-init。
4. 确认身份、文件夹、SSH 密钥、管理范围和服务端口符合意图。
5. 提供明确的变更许可和精确的文件夹确认后再创建。
6. 查看云提供方返回的资源状态，再单独运行端点诊断。
7. 检查目标范围后，仅使用归属一致、相互匹配的计划和状态文件执行销毁。

网关配置方案编译是本地操作，不访问云、不生成私钥，也不证明虚拟机就绪。首个传输实现采用受限的 SSH 本地端口转发，明确指定目标并逐设备授权。该配置方案不预设 A-VPN 产品、私有 NAS、固定国家或隐含账户。

## 在本地准备安全网关 {#prepare-a-secure-gateway-locally}

将以下内容保存为操作员控制目录中的 `gateway.toml`。这是一个示例，请在部署前填入自己的文件夹、可用区、镜像 ID、管理地址和公钥。选择符合所声明虚拟机要求的 Ubuntu 24.04 镜像和尽可能小的合适管理 CIDR。

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

允许 UDP 端口不会安装 VPN。SSH 本地转发使用配置的 SSH 端口；删除未使用的服务项并尽可能缩小范围。生成的虚拟机配置禁用密码和 root SSH 登录、IPv4 转发和 IPv6，并限制入站访问。这不会建立 IP 数据包路由，也不能证明虚拟机已就绪。独立且无 sudo 权限的隧道账号只允许声明的本地转发目标和逐设备源 CIDR；管理账户转发保持禁用。

在 POSIX 控制台中本地生成并检查归属明确的服务器制品包和生命周期计划：

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

存储组件以独占方式创建新制品包，限制访问权限，并记录资源归属和内容哈希清单，绝不覆盖现有包。`RenderPlan` 在绑定文件路径前根据配置方案验证 cloud-init 字节。产生的本地路径依赖机器；计划和制品包不得进入 Git，编译后也不要移动 cloud-init 文件。

## 生命周期命令契约 {#lifecycle-command-contract}

命令使用同一份明确指定的计划、状态文件和 CLI 命名配置：

```bash
python -m flayer lifecycle status --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --format json
python -m flayer lifecycle create --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
python -m flayer lifecycle recover --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

`status` 读取云提供方返回的资源状态。`create`、`recover` 和 `destroy` 同时要求 `--allow-mutation` 和与计划作用域 ID 精确相等的 `--scope-confirm`。它们必须使用相同的资源归属标识和操作员控制的状态路径。顶层诊断 `status` 与生命周期 `status` 分离。

创建成功证明提供方资源已建立，不证明 cloud-init 已完成或客户端能够连接。选择适合该部署的虚拟机就绪检查之后，才使用 `health` 检查明确端点。

## 恢复和清理 {#recovery-and-cleanup}

中断操作会在状态文件旁保留日志。超时的创建可能已在远程成功：恢复必须找到归属明确的逻辑资源，而不是创建副本。无法确定的缺失资源会阻止恢复，等待操作员调查。

进程崩溃可能留下协作式操作锁。手动移除前，请确认旧进程已经终止并检查日志和状态；F-Layer 不会自动擦除可能仍在使用的锁。

回滚只影响该操作创建的资源；操作前已经存在、且已核实归属并纳入管理的资源保持不变。显式清理使用：

```bash
python -m flayer lifecycle destroy --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

填入实际部署参数之前，检查真实文件夹和资源身份。删除前，必须确认云端资源的归属与计划一致。保留日志和状态，直到清理成功且中断结果得到解决。

确认云清理完成后，通过归属清单移除精确的服务器制品包，不要删除任意目录：

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

示例将 `127.0.0.1:8443` 绑定到声明的 `example.org:443` 目标。严格主机密钥检查已启用，服务器限制允许的密钥、源范围和目标。本地端口转发只承载所选连接，不提供覆盖整台设备的 VPN、IP 数据包路由或客户端自动安装。将连接视为成功前，请检查实际 SSH 和端点证据。

设备制品包有独立归属清单。不再需要时，仅使用 `RemoveArtifactBundle(..., kind="device", name="laptop")` 移除匹配制品包。私钥和可信主机密钥文件仍由操作员单独管理。
