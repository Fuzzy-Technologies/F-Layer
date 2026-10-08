# 文档规则 {#documentation-contracts}

F-Layer 采用 [Fuzzy Technologies 文档蓝图](https://github.com/Fuzzy-Technologies/FuzzyRoutines/tree/develop/docs/documentation-blueprint)：MkDocs Material、mkdocstrings-python 和 Griffe，从已安装 wheel 中静态发现。主题通过已跟踪配置、CSS 和 SVG 扩展。生成的 HTML 保持临时且不受版本控制。

## API 发现 {#api-discovery}

已安装 `flayer` 包中每个非私有 Python 模块都生成 API 页面；`flayer.__main__` 是下划线路径规则的明确受支持例外。私有模块和辅助函数仅保留源码，并记录原因。发现过程读取语法，从不导入运行时代码。导入保护使尝试执行包的构建失败。除字节码外，整个安装包必须与源码清单和字节匹配。公开定义和可调用协议要求精确的生成 HTML 锚点；每个 API 页面链接到对应 `develop` 源码。

每个已跟踪文件必须匹配且仅匹配一个明确覆盖规则。所有规范 Markdown，包括政策、发布指南、ADR、模板和仓库入口，都必须渲染并可从英文入口到达。测试、工具、工作流、示例、资源和配置具有可说明的用途，而不是虚构 API 文档。本地化覆盖内容由语言构建包装工具渲染，并显示明确审核状态。[覆盖契约](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/development/documentation-coverage.md)定义边界和机器可读证据。

每个已跟踪 Markdown 表格按列内容对齐。源码检查在发布前验证原文可读性，保留转义竖线、代码单元格、对齐标记和代码块中的字面示例。

英文作者页面使用已跟踪的语言单元登记表。动态生成的 API 单元使用临时清单，采用相同稳定符号 ID 和版本化源码哈希。目标语言状态明确为 `missing`；生成清单不能制造译文或审核。

## 语言和审核 {#language-and-review}

英文是规范来源。已登记的俄文和简体中文草稿可由多语言构建包装工具渲染，并显示明确审核状态横幅。缺失或过时单元使用最新英文回退文本。语言导航和页面横幅区分 `draft`、`review`、`stale`、`missing`、`approved` 状态；自动化从不生成人工批准。

每个非缺失译文记录 `basedOnSourceHash`，即实际使用的英文源文。更新规范登记表不能隐藏过时草稿。人工语言审核和实际 Pages 发布仍未完成。

只有具备稳定单元 ID、匹配的规范源码哈希、译文路径及可追责的人工编辑和技术审核，`approved` 才有效。自动化可以检测漂移并生成 `missing` 记录，从不生成批准。术语存储在各语言概念对齐的术语表中。

## 发布 {#publication}

Pull request 和 `develop` 生成可下载的预览和证据制品。仅 `master` 分支的 `push` 事件可以部署经过验证的 Pages 制品。文档发布独立于包发布。

公开路由为 `/F-Layer/en/`、`/F-Layer/ru/` 和 `/F-Layer/zh-CN/`。根路径打开英文参考。在稳定发布之前，不宣称拥有不可变版本文档。

[ADR 0004](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/adr/0004-documentation-platform.md)记录已接受的生成器、审核、源码哈希、回退和发布边界。
