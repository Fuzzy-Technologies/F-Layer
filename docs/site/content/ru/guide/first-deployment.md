# Первое развёртывание {#first-deployment}

Это руководство описывает развёртывание защищённого SSH-шлюза из стабильного
выпуска. Нужны аккаунт Yandex Cloud и аутентифицированный профиль `yc`.
Список команд можно посмотреть через `python -m flayer lifecycle --help`.

Для развёртывания нужны профиль сервера, план облачных ресурсов и файл состояния. F-Layer сохраняет в нём ID созданных ресурсов, чтобы впоследствии проверять и удалять именно это развёртывание. Для сервера и каждого подключаемого устройства создаются отдельные наборы конфигурационных файлов. Учётные данные и закрытые ключи хранятся отдельно.

При сохранении конфигураций F-Layer проверяет владельца и права доступа к файлам по правилам POSIX. Для этого руководства используйте Linux или macOS. Сохранение таких файлов в Windows пока не поддерживается; установка пакета и локальная диагностика доступны отдельно.

## Порядок действий {#operator-sequence}

1. [Установите пакет](installation.md) и настройте профиль `yc`.
2. Подготовьте и локально проверьте профиль защищённого шлюза.
3. Создайте серверные файлы, проверьте план ресурсов и cloud-init.
4. Проверьте проект, каталог, SSH-ключ, адреса управления и сервисные порты.
5. Подтвердите создание ресурсов и ID каталога.
6. Проверьте состояние облачных ресурсов и подключение к серверу.
7. Для удаления используйте те же план и файл состояния; сначала проверьте, какой проект удаляете.

Подготовка плана выполняется локально, без обращения к облаку и создания закрытых ключей. Этот профиль использует SSH-проброс к заданным адресам; доступ настраивается отдельно для каждого устройства. Доступность сервера нужно проверить после развёртывания.

## Локальная подготовка защищённого шлюза {#prepare-a-secure-gateway-locally}

Сохраните пример ниже в `gateway.toml` в своём рабочем каталоге. Перед развёртыванием замените ID каталога Yandex Cloud, зону, ID образа, IP-адрес управления и открытые ключи на свои значения. Нужен образ Ubuntu 24.04 с поддержкой cloud-init. В `management_cidrs` укажите адреса, с которых вы будете администрировать сервер; для одного адреса используется маска `/32`.

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

SSH-проброс использует SSH-порт из конфигурации. Открытие дополнительных UDP-портов само по себе не устанавливает VPN-сервер. Настройки cloud-init отключают вход по паролю и вход root по SSH, IPv4 forwarding и IPv6, а также ограничивают входящие соединения. Для проброса создаётся отдельный пользователь без sudo: ему доступны только адреса из `transport.targets`, а подключения разрешены только с адресов устройств. У административного пользователя проброс портов отключён.

Создайте серверные файлы и план локально, в терминале Linux или macOS:

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

Каждый набор файлов сохраняется с ограниченными правами доступа и манифестом: в нём указаны владелец и хеши содержимого. Существующие наборы не перезаписываются. `RenderPlan` сверяет cloud-init с профилем и записывает его путь в план. Храните эти файлы вне Git и не перемещайте cloud-init после создания плана.

## Создание и проверка ресурсов {#lifecycle-command-contract}

Во всех командах используются одинаковые план, файл состояния и профиль:

```bash
python -m flayer lifecycle status --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --format json
python -m flayer lifecycle create --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
python -m flayer lifecycle recover --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

`status` запрашивает состояние ресурсов в облаке. Команды `create`, `recover` и `destroy` требуют `--allow-mutation` и `--scope-confirm` с точным ID каталога из плана. Во всех командах используйте одни и те же план, файл состояния и профиль. Обычный диагностический `status` работает отдельно от `lifecycle status`.

После успешного `create` облачные ресурсы созданы, но cloud-init внутри сервера ещё может работать. Дождитесь завершения настройки сервера и проверьте подключение клиента. Если на сервере есть HTTP-сервис, его адрес можно дополнительно проверить командой `health`.

## Восстановление и очистка {#recovery-and-cleanup}

Журнал операций сохраняется рядом с файлом состояния. Если создание завершилось по таймауту, ресурс мог успеть появиться в облаке. Команда `recover` ищет ресурс по данным проекта, владельца и плана, чтобы не создать дубликат. Если его состояние нельзя определить однозначно, восстановление останавливается до выяснения причины.

После аварийного завершения процесса может остаться файл блокировки. Прежде чем удалить его вручную, убедитесь, что старый процесс больше не работает, и изучите журнал. F-Layer не удаляет блокировку автоматически, пока она может принадлежать работающей операции.

При откате удаляются только ресурсы, созданные текущей операцией. Ресурсы этого же развёртывания, существовавшие до её начала, сохраняются. Чтобы удалить всё развёртывание:

```bash
python -m flayer lifecycle destroy --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

Перед удалением проверьте ID каталога, имя проекта и имя развёртывания. F-Layer также сверит принадлежность ресурсов по данным облака. Сохраняйте журнал и файл состояния, пока удаление не завершится успешно и не останется прерванных операций.

После удаления облачных ресурсов можно удалить локальный набор серверных файлов. Используйте его манифест, чтобы удалить только файлы этого развёртывания:

```python
from flayer.profiles import LoadGatewayProfile, RemoveArtifactBundle

profile = LoadGatewayProfile("gateway.toml")
RemoveArtifactBundle(
    "generated-artifacts", profile.identity, kind="server", name=profile.identity.stack,
)
```

## Подключение одного авторизованного устройства {#connect-one-authorized-device}

Подготовьте закрытый ключ устройства, соответствующий открытому ключу из `transport.devices`. Получите ключ SSH-сервера через доверенный канал, проверьте его и сохраните в файле `known_hosts`. Генератор не читает закрытые ключи и не принимает незнакомый ключ сервера автоматически.

Узнав публичный IP-адрес сервера, создайте конфигурацию SSH-клиента:

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

`203.0.113.42` приведён для примера. Замените его публичным IP-адресом сервера, а пути — путями к своему закрытому ключу и файлу `known_hosts`. Эти пути должны существовать на устройстве, где будет запущен клиент. Запустите проброс и оставьте команду работающей:

```bash
ssh -F generated-artifacts/device-laptop/ssh-client.conf -N laptop
```

Теперь соединения к `127.0.0.1:8443` проходят через сервер к `example.org:443`. SSH проверяет ключ сервера, а сервер ограничивает допустимые ключи устройств, адреса подключений и цели проброса. Этот пример передаёт одно выбранное соединение, а не весь трафик устройства. Проверьте, что SSH подключился и целевой сервис доступен.

Для каждого устройства сохраняется отдельный манифест файлов. Ненужную конфигурацию можно удалить через `RemoveArtifactBundle(..., kind="device", name="laptop")`. Закрытый ключ устройства и файл `known_hosts` эта операция не удаляет.