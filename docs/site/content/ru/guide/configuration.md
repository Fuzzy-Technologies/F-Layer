# Конфигурация и доступ к провайдеру {#configuration-and-provider-access}

В конфигурации указывают проект, профиль развёртывания и ресурсы, которые нужно
создать. По именам проекта и развёртывания F-Layer затем определяет, какие
ресурсы ему принадлежат. Чтение файла только проверяет настройки. Доступ к
Yandex Cloud настраивается отдельно через `yc`, как показано ниже. Токены
доступа и закрытые ключи в конфигурацию добавлять не нужно.

## Имена проекта и ресурсов {#explicit-identity}

Пример файла `intent.toml` в формате версии `1`:

```toml
schema_version = 1
profile = "secure-gateway"

[identity]
project = "example-project"
stack = "example-stack"
provider = "yandex-cloud"
scope_id = "example-folder"
owner_id = "example-owner"

[[resources]]
logical_id = "gateway"
kind = "instance"
name = "example-gateway"
```

Это пример. Замените `scope_id` на ID своего каталога Yandex Cloud, а также
задайте собственные имена проекта (`project`), развёртывания (`stack`) и
владельца (`owner_id`). Имена начинаются с буквы и могут содержать строчные
латинские буквы, цифры и дефисы. Для ID облачного каталога действуют отдельные
правила. F-Layer отклоняет неизвестные поля, повторяющиеся `logical_id` и
неподдерживаемые версии формата.

Чтобы проверить файл без обращения к облаку:

```python
from flayer.core.config import LoadConfig

config = LoadConfig("intent.toml")
print(config.identity.project, config.profile)
```

Этот файл описывает имена ресурсов. Для создания сервера нужен также план:
он содержит параметры облачных ресурсов и порядок их создания. F-Layer
формирует такой план из профиля шлюза вместе с настройками безопасности
сервера. Полный пример есть в [руководстве по развёртыванию](first-deployment.md).

## Подключение к Yandex Cloud {#existing-yandex-cli-authentication}

Установите [CLI Yandex Cloud по русскоязычной инструкции](https://yandex.cloud/ru/docs/cli/quickstart)
и настройте профиль с доступом к своему облаку. Запишите имя профиля и ID
каталога, в котором будете создавать ресурсы. Эти значения передаются
F-Layer явно; каталог из настроек `yc` по умолчанию не используется.

```bash
yc --version
```

Следующий пример подключается к выбранному каталогу и считает виртуальные машины:

```python
from flayer.providers.contracts import ResourceKind
from flayer.providers.yandex import YandexCloudProvider, YandexCloudSettings

provider = YandexCloudProvider(
    YandexCloudSettings(folder_id="example-folder", profile="example")
)
status = provider.CheckAuthentication()

if status.authenticated:
    instances = provider.ListResources(ResourceKind.INSTANCE)
    print(len(instances))
```

Замените `example-folder` и `example` на ID каталога и имя профиля. F-Layer
передаёт их в каждую команду `yc` и проверяет, что полученные ресурсы находятся
в нужном каталоге. Для создания и удаления ресурсов нужны дополнительные права;
успешная проверка чтения их не подтверждает. Сообщения об ошибках не содержат
полный вывод `yc`, в котором могут оказаться чувствительные данные. Типы
результатов описаны в [архитектуре](../architecture.md) и
[справочнике API](../api/index.md).

## Учётные данные и файл состояния {#credentials-and-durable-state}

Если приложение использует запись `credentials`, в ней указывают **имя источника** учётных данных:

```toml
[[credentials]]
name = "provider-auth"
source = "env"
reference = "EXAMPLE_PROVIDER_AUTH"
```

При чтении конфигурации сохраняется имя переменной, а её значение не читается.
Для Yandex Cloud эта запись не нужна: подключение использует настроенный
профиль `yc`. Добавление `credentials` само по себе не настраивает доступ к облаку.

Файл состояния хранит ID созданных облачных ресурсов и сведения о проекте,
развёртывании и владельце. Он нужен для проверки состояния, восстановления
прерванных операций и удаления ресурсов. Храните его в своём рабочем каталоге
и не добавляйте в Git. F-Layer проверяет принадлежность ресурсов перед
изменением; чужой файл состояния или подмена владельца не дают права ими управлять.
