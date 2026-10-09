# 开发 {#development}

F-Layer 使用 `master` 进行稳定发布，使用 `develop` 进行集成，并在范围明确的 `feature/*` 或 `fix/*` 分支上实现变更。Pull request 以 `develop` 为目标并需要人工审核。

修改前请阅读 [AGENTS.md](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/AGENTS.md) 和[开发协议](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/DEVELOPMENT_PROTOCOL.md)。

## Python 验证 {#python-validation}

```bash
python -m pip install -e ".[dev]"
python -m compileall -q src tests tools
python -m ruff check .
python -m mypy
python -m pytest
```

源码、注释、文档字符串、测试和规范文档均使用英文。[Python 风格契约](../../../development/PYTHON_CODE_STYLE.md)是权威规则。

## 基础设施安全 {#infrastructure-safety}

本地测试使用模拟对象、固定测试数据和确定性数据，不创建、更新或删除真实云资源。文档发现不会导入 F-Layer 运行时包。

## 构建本参考文档 {#build-this-reference}

```bash
python tools/build_api_reference.py
```

该命令构建 wheel，并在隔离环境中安装它及所有版本固定的文档工具。它以严格模式构建 MkDocs 站点，检查精确的渲染锚点和本地链接，验证语言元数据，并在 `_build/api-reference/` 中记录 wheel 来源。

Markdown 表格按每列最宽单元格补齐，便于阅读 Markdown 源文件。使用 `python -m tools.markdown_tables` 检查所有已跟踪 Markdown；如已明确要求调整表格对齐，可运行 `python -m tools.markdown_tables --write`，该命令只修改空白。代码块中的示例不会改变。文档构建会拒绝不符合对齐规则的表格以及失效链接和锚点。

```bash
python tools/build_api_reference.py --serve
```

预览在 `127.0.0.1:8000` 使用同一份已验证的安装包输出。发布和本地化详情见[文档规则](documentation.md)。
