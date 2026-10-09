# Быстрый старт {#quick-start}

Создадим небольшой сервер в Yandex Cloud, подключимся через него и удалим
ресурсы после проверки. Стабильная версия **v1.2.1** использует SSH-шлюз:
он передаёт выбранные соединения через сервер. Сценарий с двумя VPN-протоколами
готовится для версии 2.0 и пока не входит в этот стабильный пакет.

## 1. Проверьте установку {#1-check-the-installation}

[Установите готовый пакет](installation.md) и выполните:

```bash
flayer check --format json
```

Ожидаемый результат: `"status": "ok"`, код завершения `0`. Значит, пакет
установлен и запускается. Доступ к облаку настроим следующим шагом.

## 2. Подключите аккаунт Yandex Cloud {#2-connect-your-yandex-cloud-account}

Для этого руководства используйте Linux или macOS. Установите и настройте
[CLI Yandex Cloud по русскоязычной инструкции](https://yandex.cloud/ru/docs/cli/quickstart),
затем проверьте доступные профили:

```bash
yc --version
yc config profile list
```

Запишите имя профиля и ID каталога облака, в котором хотите создать сервер.
В командах ниже замените `example` на имя профиля, а `example-folder` — на ID
каталога. Аккаунту нужны права на создание и удаление вычислительных и сетевых
ресурсов в этом каталоге. За используемые ресурсы Yandex Cloud взимает плату.

## 3. Подготовьте настройки сервера {#3-prepare-the-server-settings}

Скопируйте пример `gateway.toml` из раздела
[«Первое развёртывание»](first-deployment.md#prepare-a-secure-gateway-locally)
в новый рабочий каталог. Укажите ID каталога облака, зону доступности, ID образа
Ubuntu 24.04, адреса для административного доступа и свои открытые SSH-ключи.
Пример создаёт сеть, подсеть, межсетевой экран, публичный IP-адрес,
загрузочный диск и виртуальную машину.

Выполните приведённый там код локальной подготовки. Он создаст файл cloud-init
с настройками сервера и план `generated-artifacts/plan.toml`. Проверьте оба файла
перед созданием ресурсов. Остальные команды выполняйте из того же рабочего
каталога, где хранятся конфигурация и созданные файлы.

## 4. Создайте и проверьте развёртывание {#4-create-and-inspect-the-deployment}

```bash
flayer lifecycle create --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
flayer lifecycle status --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --format json
```

Первая команда создаёт облачные ресурсы и записывает их ID в `stack.json`.
Вторая получает их текущее состояние. Сохраните файл состояния: он нужен
для восстановления и удаления ресурсов. Если создание прервалось, следуйте
[инструкции по восстановлению](first-deployment.md#recovery-and-cleanup).

Дождитесь завершения cloud-init и выполните шаги из раздела
[«Подключение одного устройства»](first-deployment.md#connect-one-authorized-device):
создайте конфигурацию клиента и запустите SSH-соединение. В примере обращения
к `127.0.0.1:8443` проходят через сервер к `example.org:443`. Проверьте само
подключение: работающая виртуальная машина ещё не означает доступность сервиса.

## 5. Удалите ресурсы {#5-remove-the-resources}

После проверки убедитесь, что указаны нужные каталог и проект, и выполните:

```bash
flayer lifecycle destroy --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

Проверьте результат команды и состояние облака, прежде чем удалять файл
состояния. Удаление созданных локальных файлов также описано в руководстве.

## Другие сценарии {#other-ways-to-use-f-layer}

Чтобы проверить уже работающий HTTP-сервис, подставьте его адрес:

```bash
flayer health --endpoint https://example.com/ --timeout 3 --format json
```

Проверки и коды завершения описаны в [руководстве CLI](cli.md). Для работы
из Python начните с [конфигурации](configuration.md) и [справочника API](../api/index.md).
Сейчас из облачных провайдеров реализован Yandex Cloud; для подключения
других облаков потребуется отдельный адаптер.

Фигурные скобки в справке, например `{create,status,destroy,recover}`, означают:
**выберите одну команду**. Вводить сами скобки не нужно.
