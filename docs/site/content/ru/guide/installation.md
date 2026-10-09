# Установка {#install}

F-Layer — пакет Python. Нужен **Python 3.11 или новее**. Для установки готового
выпуска Git и Docker не нужны. Пакет распространяется под именем `f-layer`,
а модуль Python и команда называются `flayer`.

## Установите готовый пакет {#install-the-release-package}

Создайте отдельное окружение Python:

```bash
python -m venv .venv
```

| Консоль                  | Активация                    |
| ------------------------ | ---------------------------- |
| Linux/macOS bash или zsh | `source .venv/bin/activate`  |
| Windows PowerShell       | `.venv\Scripts\Activate.ps1` |
| Windows Command Prompt   | `.venv\Scripts\activate.bat` |

Скачайте `f_layer-2.0.0-py3-none-any.whl` и `build-evidence.json` из
[файлов релиза](https://github.com/Fuzzy-Technologies/F-Layer/releases).
Сверьте SHA-256 wheel с отчётом сборки. В каталоге скачанных файлов установите
F-Layer 2.0 с дополнением `vpn`:

```bash
python -m pip install "./f_layer-2.0.0-py3-none-any.whl[vpn]"
flayer --help
flayer check --format json
flayer project --help
flayer vpn --help
```

Ожидаемый результат: `"status": "ok"` и код завершения `0`. Команды `flayer`
и `python -m flayer` принимают одинаковые аргументы. Далее используйте
[быстрый старт VPN](index.md) или [инструкцию по SSH-шлюзу](first-deployment.md)
для ограниченных SSH-пробросов.

Дополнение `vpn` устанавливает криптографическую библиотеку для локального
создания ключей. В файлах релиза также доступны архив исходников и отчёт сборки
с ревизией кода и хешами артефактов. Сохраните этот отчёт вместе с пакетом.

Запускайте контроллер развёртывания VPN в Linux или пользовательском
Linux-дистрибутиве WSL с OpenSSH и CLI Yandex Cloud. Приватные файлы проекта
используют права доступа и владельца по правилам POSIX. В Windows можно
проверить пакет; для развёртывания используйте окружение WSL.

## Установка для разработки {#development-checkout}

Git нужен участникам разработки. Чтобы работать с веткой `develop`:

```bash
git clone --branch develop https://github.com/Fuzzy-Technologies/F-Layer.git
cd F-Layer
python -m pip install -e ".[dev]"
```

Во время разработки запускайте тесты затронутых функций. Полный набор проверок
выполняет CI при открытии pull request. Команды тестирования и сборки
документации описаны в [руководстве разработчика](../development.md).

## Проблемы установки {#installation-issues}

| Признак                           | Что сделать                                                                       |
| --------------------------------- | --------------------------------------------------------------------------------- |
| `No module named flayer`          | Активируйте окружение, в которое устанавливали пакет, и установите wheel ещё раз. |
| `python` недоступен               | Используйте команду запуска Python 3.11+, например `python3` или `py -3.11`.      |
| `flayer` недоступен               | Активируйте окружение или запускайте `python -m flayer`.                          |
| Активация в Windows заблокирована | Используйте `.venv\Scripts\python.exe` напрямую для установки и запуска.          |

Храните учётные данные, созданные конфигурации клиентов и состояние
развёртывания вне репозитория исходников.
