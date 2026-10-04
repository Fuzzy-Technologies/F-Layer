# Первое развёртывание {#first-deployment}

!!! info "Интеграция второй волны"
    Базовый пакет обнаруживает ресурсы провайдера только для чтения. Это руководство требует задач жизненного цикла #20 и защищённого шлюза #22 в установленной ревизии. Их отсутствие означает недоступную функцию, а не успешное развёртывание. Перед командами проверьте `python -m flayer lifecycle --help`.

Развёртывание состоит из явной идентичности стека, скомпилированного плана ресурсов, локального состояния с владением и ограниченных операций провайдера. Защищённый шлюз добавляет проверенный профиль сервера и отдельно принадлежащие устройства артефакты. Учётные данные и закрытые ключи не входят в планы и документацию.

Хранилище защищённых артефактов требует POSIX-проверок владельца и прав, а также файловых операций относительно дескриптора. Для этого руководства используйте Linux/macOS; сохранение в Windows не поддерживается до появления эквивалентного ACL-контракта. Установка и офлайн-диагностика — отдельные возможности.

## Последовательность оператора {#operator-sequence}

1. Установите нужную ревизию исходников и настройте существующий профиль `yc`.
2. Подготовьте и локально проверьте профиль защищённого шлюза.
3. Создайте артефакты сервера и изучите план жизненного цикла и cloud-init.
4. Проверьте идентичность, папку, SSH-ключ, диапазоны управления и сервисные порты.
5. Создавайте ресурсы с явным согласием на изменения и точным подтверждением папки.
6. Изучите наблюдения провайдера; диагностику адреса выполните отдельно.
7. Удаляйте через соответствующие план и состояние с владением после проверки области операции.

Компиляция профиля шлюза локальна: она не обращается к облаку, не создаёт закрытые ключи и не доказывает готовность гостевой системы. Первый транспорт — ограниченный локальный SSH-проброс с явной целью и авторизацией каждого устройства. Профиль не предполагает продукт A-VPN, частный NAS, фиксированную страну или неявный аккаунт.

## Локальная подготовка защищённого шлюза {#prepare-a-secure-gateway-locally}

Сохраните следующий текст как `gateway.toml` в каталоге оператора. Папка, зона, образ, адрес управления и открытые ключи синтетические — замените их перед развёртыванием. Выберите образ Ubuntu 24.04, совместимый с явным контрактом гостевой системы, и минимальные подходящие CIDR управления.

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

Разрешённый UDP-порт не устанавливает VPN. SSH-проброс использует заданный SSH-порт; удалите неиспользуемые сервисы и по возможности сузьте диапазоны. Созданная гостевая конфигурация отключает парольный и root-вход SSH, IPv4 forwarding и IPv6, ограничивает входящий доступ. Она не задаёт маршрутизацию пакетов и не доказывает готовность. Отдельный транспортный аккаунт без sudo разрешает только объявленные цели локального проброса и исходные CIDR устройств; административный проброс отключён.

После установки задачи #22 создайте и изучите серверный набор и план жизненного цикла локально из POSIX-консоли:

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

Хранилище создаёт новый набор исключительно с ограниченными правами и манифестом владения и хешей. Существующие наборы не перезаписываются. `RenderPlan` проверяет байты cloud-init по профилю перед привязкой пути. Полученный путь зависит от машины; держите план и набор вне Git и не перемещайте cloud-init после компиляции.

## Контракт команд жизненного цикла {#lifecycle-command-contract}

Когда доступна задача #20, команды используют один и тот же явный план, состояние и профиль:

```bash
python -m flayer lifecycle status --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --format json
python -m flayer lifecycle create --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
python -m flayer lifecycle recover --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

`status` читает наблюдения провайдера. `create`, `recover` и `destroy` требуют одновременно `--allow-mutation` и `--scope-confirm`, точно равный ID области плана. Владение и путь состояния под контролем оператора должны совпадать. Верхнеуровневый диагностический `status` отделён от `status` жизненного цикла.

Успешное создание устанавливает ресурсы провайдера, но не доказывает завершение cloud-init или подключение клиента. Проверяйте явный адрес командой `health` только после выбора подходящих проверок готовности гостевой системы.

## Восстановление и очистка {#recovery-and-cleanup}

Прерванные операции сохраняют журнал рядом с файлом состояния. Создание с таймаутом могло завершиться удалённо: восстановление должно найти точно принадлежащий логический ресурс, а не создавать дубликат. Неопределённо отсутствующий ресурс блокирует восстановление до расследования оператором.

Аварийное завершение процесса может оставить кооперативную блокировку операции. Перед ручным удалением блокировки убедитесь, что старый процесс завершён, и изучите журнал и состояние; F-Layer не удаляет автоматически потенциально активную блокировку.

Откат применяется к ресурсам, созданным этой операцией; ранее существовавшие точные ресурсы с подтверждённым владением остаются. Явная очистка выполняется так:

```bash
python -m flayer lifecycle destroy --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

Перед подстановкой рабочих значений проверьте реальную папку и идентичность ресурсов. Перед удалением владение у провайдера должно совпасть. Сохраняйте журнал и состояние до успешной очистки и разрешения прерванных исходов.

После подтверждения облачной очистки удалите точный серверный набор через манифест владения, а не произвольный каталог:

```python
from flayer.profiles import LoadGatewayProfile, RemoveArtifactBundle

profile = LoadGatewayProfile("gateway.toml")
RemoveArtifactBundle(
    "generated-artifacts", profile.identity, kind="server", name=profile.identity.stack,
)
```

## Подключение одного авторизованного устройства {#connect-one-authorized-device}

Самостоятельно подготовьте закрытый ключ устройства, соответствующий открытому ключу в `transport.devices`. Получите и проверьте ключ сервера через доверенный канал и поместите его в явный файл `known_hosts`. Генератор не читает закрытые ключи и не принимает первый наблюдённый ключ сервера за доверенный.

Создайте рабочую SSH-конфигурацию устройства после определения фактического адреса сервера и доверенных путей:

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

`203.0.113.42` — адрес для документации. Замените его наблюдаемым адресом и явными локальными путями к ключу и доверенным данным; созданные пути непереносимы. Затем держите локальный проброс запущенным:

```bash
ssh -F generated-artifacts/device-laptop/ssh-client.conf -N laptop
```

Пример связывает `127.0.0.1:8443` с объявленной целью `example.org:443`. Строгая проверка ключа сервера включена; сервер ограничивает ключи, исходные диапазоны и цели. Локальный проброс переносит выбранное соединение; это не VPN всего устройства, не маршрутизатор пакетов и не автоматическая установка клиента. Проверяйте фактические SSH-свидетельства и адрес, прежде чем считать подключение успешным.

Наборы устройств имеют независимые манифесты владения. Когда набор больше не нужен, удалите только соответствующий набор через `RemoveArtifactBundle(..., kind="device", name="laptop")`. Закрытые ключи и файлы доверенных ключей сервера остаются отдельными входными данными оператора.
