# 文档规则 {#documentation-contracts}

F-Layer 采用 [Fuzzy Technologies 文档蓝图](https://github.com/Fuzzy-Technologies/FuzzyRoutines/tree/develop/docs/documentation-blueprint)：MkDocs Material、mkdocstrings-python 和 Griffe，从已安装 wheel 中静态发现。主题通过已跟踪配置、CSS 和 SVG 扩展。生成的 HTML 保持临时且不受版本控制。

## API 发现 {#api-discovery}

已安装 `flayer` 包中每个非私有 Python 模块都生成 API 页面；`flayer.__main__` 是下划线路径规则的明确受支持例外。私有模块和辅助函数仅保留源码，并记录原因。发现过程读取语法，从不导入运行时代码。导入保护使尝试执行包的构建失败。除字节码外，整个安装包必须与源码清单和字节匹配。公开定义和可调用协议要求精确的生成 HTML 锚点；每个 API 页面链接到对应 `develop` 源码。

每个已跟踪文件必须匹配且仅匹配一个明确覆盖规则。所有规范 Markdown，包括政策、发布指南、ADR、模板和仓库入口，都必须渲染并可从英文入口到达。测试、工具、工作流、示例、资源和配置具有可说明的用途，而不是虚构 API 文档。本地化覆盖内容由语言构建包装工具渲染，并显示明确审核状态。[覆盖契约](../../../development/documentation-coverage.md)定义边界和机器可读证据。

每个已跟踪 Markdown 表格按列内容对齐。源码检查在发布前验证原文可读性，保留转义竖线、代码单元格、对齐标记和代码块中的字面示例。

英文作者页面使用已跟踪的语言单元登记表。动态生成的 API 单元使用临时清单，采用相同稳定符号 ID 和版本化源码哈希。出现在清单中不代表已经翻译或审核；状态由实际译文和审核记录决定。

## 语言和审核 {#language-and-review}

英文是规范来源。应项目所有者要求，AIna-Dev 已将俄文和简体中文作者页面
与英文源文逐一核对。已审核的页面直接显示正文，不显示草稿提示。
缺失或过时的译文显示最新英文原文，并附有回退提示。
这一规则同样适用于尚未翻译的 API 页面和工程参考。

每份译文记录稳定单元 ID、英文源文哈希及路径。批准需要具名的编辑审核
和技术审核、UTC 时间戳及当前源文哈希。F-Layer 根据
[ADR 0015](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/adr/0015-accountable-ai-translation-review.md)
明确允许 AI 审核。这些记录将审核者标记为 AI，并额外记录已审核译文的文本哈希；
它们不代表人工审核。任一文本发生变化都需要重新审核，
仅更新英文登记表不能恢复批准状态。

术语保存在各语言对应的术语表中。审核来源可在已跟踪登记表和构建证据中查阅。

## 发布 {#publication}

Pull request 和 `develop` 生成可下载的预览和证据制品。仅 `master` 分支的 `push` 事件可以部署经过验证的 Pages 制品。文档发布独立于包发布。

公开路由为 `/F-Layer/en/`、`/F-Layer/ru/` 和 `/F-Layer/zh-CN/`。根路径打开英文参考。

[ADR 0004](../../../adr/0004-documentation-platform.md)记录已接受的生成器、审核、源码哈希、回退和发布边界。
