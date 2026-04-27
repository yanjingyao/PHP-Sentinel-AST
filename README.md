# PHP-Sentinel — AST 漏洞检测引擎

基于 AST（抽象语法树）的 PHP 代码安全审计平台。支持污点传播分析、WebShell 检测、AI 辅助审计，提供可视化仪表盘与多种格式报告导出。

## 核心功能

- **AST 污点分析** — 基于 `phply` 解析 PHP AST，追踪 `$_GET` / `$_POST` 等输入源经过赋值、拼接、函数调用后的数据流，判断是否在无净化的情况下到达危险 Sink（如 `eval`、`mysql_query`、`system`）
- **WebShell 专项检测** — 内置 WebShell 特征匹配规则，识别一句话木马、变种免杀等恶意代码
- **14 类漏洞覆盖** — SQL 注入、XSS、RCE、文件包含 (LFI/RFI)、SSRF、反序列化、任意文件操作、不安全上传、HTTP 头部注入、LDAP 注入、弱加密等
- **AI 辅助审计** — 支持 Gemini / OpenAI / Moonshot 多模型，对检出漏洞进行误报判定、PoC 生成和交互式对话
- **可视化仪表盘** — 风险分布饼图、漏洞类型柱状图、历史扫描趋势
- **多格式报告导出** — HTML / JSON / SARIF，支持一键导出
- **自定义规则** — 支持添加、启用/禁用自定义正则规则，与内置规则协同工作
- **Monaco Editor** — 代码编辑器内嵌，漏洞行高亮、文件树浏览
- **网络实验室** — 内置 HTTP 代理转发，可用于复现 SSRF / HTTP 注入类漏洞
- **WebSocket 实时进度** — 后台扫描任务通过 WebSocket 推送扫描进度

## 技术栈

| 层 | 技术 |
|---|---|
| 前端 | React 19、TypeScript、Vite、Tailwind CSS 4、Monaco Editor、Recharts |
| 后端 | Python FastAPI、SQLAlchemy (async)、aiosqlite |
| AST 引擎 | phply（PHP AST 解析器） |
| AI | Gemini / OpenAI / Moonshot 多模型支持 |

## 快速开始

### 1. 安装依赖

```bash
# 前端依赖
npm install

# 后端依赖 (Python 3.10+)
pip install fastapi uvicorn sqlalchemy aiosqlite pydantic-settings phply aiofiles
```

### 2. 配置环境变量

在项目根目录或 `backend/src/` 下创建 `.env` 文件：

```env
# AI API Key（至少配置一个）
GEMINI_API_KEY=your_gemini_api_key
OPENAI_API_KEY=your_openai_api_key
MOONSHOT_API_KEY=your_moonshot_api_key

# 可选配置
DEFAULT_AI_PROVIDER=gemini
DEFAULT_AI_MODEL=gemini-pro
DEBUG=false
```

### 3. 启动

```bash
# 同时启动前后端
npm run dev:all

# 或分别启动
npm run dev          # 前端 → http://localhost:3000
npm run dev:backend  # 后端 → http://localhost:8000
```

### 4. 使用

1. 在扫描页面点击上传或拖拽 PHP 项目文件夹
2. 点击「开始扫描」执行审计
3. 查看漏洞列表，点击漏洞可跳转到代码对应行
4. 对疑似漏洞可使用 AI 审计进行二次确认
5. 在仪表盘查看统计图表，导出报告

## 检测原理

```
Source (用户输入)  →  Propagation (数据传播)  →  Sanitizer?  →  Sink (危险函数)
     ↓                                                    ↓              ↓
  $_GET, $_POST        赋值 / 拼接 / 函数调用          过滤函数       eval, system,
  $_REQUEST, ...                                     是否存在？     mysql_query, ...
```

- **Source** — PHP 超全局变量（`$_GET`、`$_POST`、`$_REQUEST`、`$_COOKIE`、`$_FILES`、`$_SERVER`、`$_SESSION`、`$_ENV`）以及动态输入函数
- **Sanitizer** — 过滤/净化函数（`intval`、`htmlspecialchars`、`mysqli_real_escape_string`、`escapeshellarg` 等 20+）
- **Sink** — 危险函数（`eval`、`system`、`mysql_query`、`shell_exec`、`include`、`unserialize`、`curl_init` 等 40+）

若污点数据从 Source 流向 Sink 且中间未被有效净化，则报告为漏洞。

## 项目结构

```
├── App.tsx                   # 前端主组件
├── components/               # React UI 组件
│   ├── Layout.tsx            # 标签页布局
│   ├── Dashboard.tsx         # 仪表盘（统计图表）
│   ├── RuleConfig.tsx        # 规则管理
│   ├── Settings.tsx          # AI 配置
│   └── NetworkLab.tsx        # 网络实验室
├── services/                 # 前端服务层
│   ├── dbService.ts          # 后端 API 封装
│   ├── aiService.ts          # AI 审计服务
│   ├── builtInRules.ts       # 内置检测规则
│   └── exportService.ts      # 报告导出
├── frontend/src/api/         # API 客户端
├── types.ts                  # TypeScript 类型定义
├── backend/src/
│   ├── main.py               # FastAPI 入口
│   ├── config.py             # 配置管理
│   ├── models.py             # ORM 模型
│   ├── schemas.py            # Pydantic Schema
│   ├── routes/               # API 路由
│   │   ├── scans.py          # 扫描管理 + WebSocket
│   │   ├── vulnerabilities.py
│   │   ├── ai.py             # AI 代理
│   │   └── ...
│   └── services/
│       ├── ast_engine.py     # AST 污点分析引擎
│       ├── file_service.py   # 文件管理
│       └── ai_service.py     # 多模型 AI 服务
└── uploads_data/             # 上传文件存储（自动创建）
```

## License

MIT
