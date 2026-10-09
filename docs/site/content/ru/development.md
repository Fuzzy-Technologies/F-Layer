# Разработка {#development}

F-Layer использует `master` для стабильной публикации, `develop` для интеграции и отдельные ветки `feature/*` или `fix/*` для реализации. Pull request направляется в `develop` и требует проверки человеком.

Перед изменениями прочитайте [AGENTS.md](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/AGENTS.md) и [протокол разработки](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/DEVELOPMENT_PROTOCOL.md).

## Проверки Python {#python-validation}

```bash
python -m pip install -e ".[dev]"
python -m compileall -q src tests tools
python -m ruff check .
python -m mypy
python -m pytest
```

Исходный код, комментарии, docstring, тесты и каноническая документация написаны на английском. [Правила стиля Python](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/development/PYTHON_CODE_STYLE.md) являются обязательными.

## Безопасность инфраструктуры {#infrastructure-safety}

Локальные тесты используют моки, фикстуры и детерминированные данные. Они не создают, не изменяют и не удаляют реальные облачные ресурсы. Генерация документации не импортирует исполняемый пакет F-Layer.

## Сборка справочника {#build-this-reference}

```bash
python tools/build_api_reference.py
```

Команда собирает wheel и устанавливает его с полностью закреплёнными версиями инструментов документации в изолированную среду. Она создаёт строгую сборку MkDocs, проверяет точные якоря и локальные ссылки, метаданные языков и записывает происхождение wheel в `_build/api-reference/`.

Таблицы Markdown выравниваются по самой широкой ячейке каждого столбца для удобства чтения исходника. Проверьте отслеживаемые Markdown-файлы командой `python -m tools.markdown_tables`; для запрошенного изменения только пробелов используйте `python -m tools.markdown_tables --write`. Примеры в блоках кода сохраняются. Сборка отклоняет неверное выравнивание, сломанные ссылки и якоря.

```bash
python tools/build_api_reference.py --serve
```

Предпросмотр использует тот же проверенный результат установленного пакета на `127.0.0.1:8000`. [Правила документации](documentation.md) описывают публикацию и локализацию.
