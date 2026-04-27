# PHP Sentinel — AST 漏洞检测引擎

<p align="center">
  <strong>基于双引擎架构的 PHP 代码安全审计平台</strong><br>
  前端正则快速扫描 + 后端 AST 深度污点分析 · 15 类漏洞覆盖 · AI 辅助审计
</p>

<p align="center">
  <img src="https://img.shields.io/badge/React-19-61DAFB?logo=react" alt="React">
  <img src="https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript" alt="TypeScript">
  <img src="https://img.shields.io/badge/Vite-6-646CFF?logo=vite" alt="Vite">
  <img src="https://img.shields.io/badge/Tailwind_CSS-4-06B6D4?logo=tailwindcss" alt="Tailwind">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/SQLite-003B57?logo=sqlite" alt="SQLite">
</p>

---

## 目录

- [核心能力](#核心能力)
- [快速开始](#快速开始)
- [检测原理](#检测原理)
- [项目结构](#项目结构)
- [API 接口](#api-接口)
- [扩展开发](#扩展开发)
- [部署说明](#部署说明)

---

## 核心能力

### 漏洞检测

覆盖 **15 种** PHP 安全漏洞类型，基于 Source → Propagation → Sanitizer → Sink 的污点传播模型：

| 漏洞类型           | 风险等级 | 典型 Sink 函数                                  |
| -------------- | ---- | ------------------------------------------- |
| SQL 注入         | 严重   | `mysql_query`, `mysqli_query`, `PDO::query` |
| 远程代码执行 (RCE)   | 严重   | `eval`, `system`, `exec`, `shell_exec`      |
| 不安全的反序列化       | 严重   | `unserialize`, `yaml_parse`                 |
| 文件上传漏洞         | 严重   | `move_uploaded_file`, `file_put_contents`   |
| 文件包含 (LFI/RFI) | 高危   | `include`, `require`, `file_get_contents`   |
| 跨站脚本 (XSS)     | 高危   | `echo`, `print`                             |
| 服务端请求伪造 (SSRF) | 高危   | `curl_init`, `fsockopen`                    |
| 路径穿越           | 高危   | `unlink`, `rename`, `mkdir`                 |
| HTTP 头部注入      | 中危   | `header`, `setcookie`                       |
| LDAP 注入        | 中危   | `ldap_search`, `ldap_list`                  |
| 弱加密 / 弱哈希      | 中危   | `md5`, `sha1`, `rand`                       |
| 敏感信息泄露         | 提示   | `phpinfo`, `var_dump`                       |
| WebShell 后门    | 严重   | 一句话木马、冰蝎、蚁剑特征                               |

### AI 辅助审计

- 支持 **OpenAI 兼容 API**（Gemini / OpenAI / Moonshot / 自定义端点）
- 一键判定漏洞是否为**误报**
- 自动生成 **PoC**（curl / httpie 格式）和攻击载荷
- 交互式对话 — 针对单个漏洞与 AI 深入讨论

### 可视化仪表盘

- 风险分布饼图（严重 / 高危 / 中危 / 低危 / 提示）
- 漏洞类型柱状图
- 历史扫描趋势图
- 扫描进度实时推送（WebSocket）

### 报告导出

支持 **HTML** / **JSON** / **SARIF** 三种格式一键导出，含 AI 审计摘要和漏洞详情。

### 自定义规则

- 内置 25 条规则可自由启用 / 禁用
- 支持添加自定义正则规则
- 与内置规则协同工作，扩展检测能力

### 网络实验室

- HTTP Repeater：自定义构造和重放请求
- 代理转发：绕过 CORS，支持内网地址（`127.0.0.1`）
- 请求历史：自动记录、可回放、可清空

### Monaco Editor

- 内嵌代码编辑器，漏洞行高亮
- 文件树浏览，点击漏洞自动跳转到对应行

---

## 快速开始

### 环境要求

- **Node.js** ≥ 18
- **Python** ≥ 3.11
- **pip**

### 1. 安装依赖

```bash
# 前端依赖
npm install

# 后端依赖
pip install fastapi uvicorn sqlalchemy aiosqlite pydantic-settings phply aiofiles
```

### 2. 启动

```bash
# 同时启动前后端（推荐）
npm run dev:all

# 或分别启动
npm run dev          # 前端 → http://localhost:3000
npm run dev:backend  # 后端 → http://localhost:8000
```

### 3. 使用流程

1. **上传项目** — 拖拽或选择 PHP 项目文件夹（ZIP 或目录）
2. **选择模式** — 常规审计 / WebShell 专项扫描
3. **开始扫描** — 前端即时反馈 + 后端 AST 深度分析
4. **查看结果** — 漏洞列表、代码高亮、污点链路
5. **AI 审核** — 对疑似漏洞进行误报判定和 PoC 生成
6. **导出报告** — HTML / JSON / SARIF 格式

---

## 检测原理

### 双引擎架构

```
用户上传 PHP 代码
       │
       ▼
┌─────────────────────────────────┐
│  前端引擎 (即时反馈)              │
│  · 25 条内置正则规则              │
│  · Source/Sink 模式匹配          │
│  · 污点变量追踪                  │
│  · 即时扫描反馈                  │
└─────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────┐
│  后端引擎 (深度分析)              │
│  · phply 解析 PHP AST            │
│  · 变量赋值传播追踪              │
│  · Sanitizer 净化函数检测        │
│  · POP 链反序列化分析            │
│  · 魔法方法独立分析              │
│  · 正则规则回退                  │
└─────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────┐
│  AI 辅助审计                     │
│  · 误报判定                      │
│  · PoC 生成                      │
│  · 修复建议                      │
└─────────────────────────────────┘
```

### 污点传播模型

```
Source (用户输入)  →  Propagation (数据传播)  →  Sanitizer?  →  Sink (危险函数)
     ↓                         ↓                       ↓              ↓
  $_GET, $_POST         赋值 / 拼接 / 函数调用      过滤函数存在?    eval, system,
  $_REQUEST, ...                                     是否有效?     mysql_query, ...
```

- **Source** — 8 类 PHP 超全局变量：`$_GET` `$_POST` `$_REQUEST` `$_COOKIE` `$_FILES` `$_SERVER` `$_SESSION` `$_ENV`
- **Sanitizer** — 21 种净化函数：`intval`, `htmlspecialchars`, `mysqli_real_escape_string`, `escapeshellarg`, `filter_var`, `password_hash` 等
- **Sink** — 45+ 危险函数，按漏洞类型分类映射

若污点数据从 Source 流向 Sink 且路径上无有效 Sanitizer，即报告漏洞。

### 特色检测

- **PDO 绑定参数识别** — 检测 `bindParam` / `execute(array(...))` 避免误报
- **POP 链分析** — 识别 `__wakeup` / `__destruct` / `__toString` / `__invoke` 魔法方法中的反序列化利用链
- **动态方法调用检测** — 识别 `$obj->$var()` 模式的变量函数调用风险
- **Laravel 框架规则** — 覆盖 `DB::raw()` 等框架特有 Sink

---

## 项目结构

```
php-sentinel/
├── components/                 # React UI 组件
│   ├── Layout.tsx              # 标签页布局
│   ├── Dashboard.tsx           # 仪表盘（饼图 / 柱状图 / 趋势）
│   ├── VulnerabilityCard.tsx   # 漏洞卡片（代码定位 + AI 审计入口）
│   ├── VulnerabilityItem.tsx   # 漏洞列表项
│   ├── RuleConfig.tsx          # 规则管理（启用 / 禁用 / 自定义）
│   ├── Settings.tsx            # AI 配置（模型 / API Key / 端点）
│   └── NetworkLab.tsx          # 网络实验室（HTTP Repeater）
├── services/                   # 前端服务层
│   ├── builtInRules.ts         # 25 条内置检测规则
│   ├── dbService.ts            # 后端 API 封装（项目 / 扫描 / 文件）
│   ├── aiService.ts            # AI 审计服务（误报判定 / PoC 生成）
│   └── exportService.ts        # 报告导出（HTML / JSON / SARIF）
├── frontend/src/api/           # API 客户端层
│   ├── client.ts               # Axios 实例（baseURL / 拦截器）
│   ├── projects.ts             # 项目 CRUD
│   ├── files.ts                # 文件上传 / 下载
│   ├── scans.ts                # 扫描任务 + WebSocket
│   ├── vulnerabilities.ts      # 漏洞查询 / AI 审计 / 对话
│   ├── rules.ts                # 规则 CRUD
│   ├── settings.ts             # AI 配置持久化
│   ├── network.ts              # 代理转发 / 请求历史
│   └── ai-proxy.ts             # AI 代理请求
├── types.ts                    # TypeScript 类型 & 枚举定义
├── backend/src/
│   ├── main.py                 # FastAPI 入口（路由注册 / CORS / 生命周期）
│   ├── config.py               # Pydantic Settings（数据库 / AI / 上传路径）
│   ├── database.py             # SQLAlchemy async engine & session
│   ├── models.py               # ORM 模型（7 张表）
│   ├── schemas.py              # Pydantic Schema（请求 / 响应验证）
│   ├── routes/
│   │   ├── projects.py         # 项目管理
│   │   ├── files.py            # 文件上传 / 存储
│   │   ├── scans.py            # 扫描任务 + WebSocket 进度推送
│   │   ├── vulnerabilities.py  # 漏洞查询 / 批量创建 / AI 审计
│   │   ├── ai.py               # AI 代理路由
│   │   ├── rules.py            # 规则管理
│   │   ├── settings.py         # AI 配置存取
│   │   └── network.py          # HTTP 代理转发 + 日志
│   └── services/
│       ├── ast_engine.py       # AST 污点分析引擎（phply）
│       ├── ai_service.py       # 多模型 AI 服务
│       └── file_service.py     # 文件存储管理
└── uploads_data/               # 上传文件存储（自动创建）
```

---

## API 接口

### 项目管理

| 方法     | 端点                   | 说明        |
| ------ | -------------------- | --------- |
| GET    | `/api/projects`      | 获取所有项目    |
| POST   | `/api/projects`      | 创建项目      |
| GET    | `/api/projects/{id}` | 获取项目详情    |
| PUT    | `/api/projects/{id}` | 更新项目      |
| DELETE | `/api/projects/{id}` | 删除项目及关联数据 |

### 文件管理

| 方法   | 端点                               | 说明         |
| ---- | -------------------------------- | ---------- |
| POST | `/api/files/upload/{project_id}` | 上传 ZIP 文件包 |
| GET  | `/api/files?project_id={id}`     | 获取项目文件列表   |
| GET  | `/api/files/{id}`                | 获取文件内容     |

### 扫描任务

| 方法     | 端点                           | 说明             |
| ------ | ---------------------------- | -------------- |
| POST   | `/api/scans`                 | 创建扫描任务         |
| GET    | `/api/scans?project_id={id}` | 获取扫描历史         |
| GET    | `/api/scans/{id}`            | 获取扫描详情及漏洞      |
| DELETE | `/api/scans/{id}`            | 删除扫描记录         |
| **WS** | `/api/scans/{id}/ws`         | WebSocket 实时进度 |

### 漏洞管理

| 方法     | 端点                                  | 说明        |
| ------ | ----------------------------------- | --------- |
| GET    | `/api/vulnerabilities?scan_id={id}` | 获取扫描漏洞列表  |
| POST   | `/api/vulnerabilities/batch`        | 批量写入漏洞    |
| POST   | `/api/vulnerabilities/{id}/review`  | AI 审计单个漏洞 |
| POST   | `/api/vulnerabilities/{id}/chat`    | AI 对话     |
| DELETE | `/api/vulnerabilities/{id}`         | 删除漏洞      |

### AI 代理

| 方法   | 端点               | 说明     |
| ---- | ---------------- | ------ |
| POST | `/api/ai/review` | 代理审计请求 |
| POST | `/api/ai/chat`   | 代理对话请求 |

### 规则管理

| 方法     | 端点                | 说明               |
| ------ | ----------------- | ---------------- |
| GET    | `/api/rules`      | 获取所有规则（内置 + 自定义） |
| POST   | `/api/rules`      | 创建自定义规则          |
| PUT    | `/api/rules/{id}` | 更新规则启用状态         |
| DELETE | `/api/rules/{id}` | 删除自定义规则          |

### 网络代理

| 方法     | 端点                   | 说明           |
| ------ | -------------------- | ------------ |
| POST   | `/api/network/proxy` | 代理转发 HTTP 请求 |
| GET    | `/api/network/logs`  | 获取请求历史       |
| DELETE | `/api/network/logs`  | 清空历史         |

---

## 扩展开发

### 添加 Sink（危险函数）

后端 `backend/src/services/ast_engine.py`：

```python
SINKS: Dict[str, SinkSpec] = {
    # 新增自定义 Sink
    "dangerous_custom_func": SinkSpec(
        VulnerabilityType.CODE_EXECUTION,
        RiskLevel.CRITICAL,
        require_taint=True,
    ),
}
```

### 添加内置规则

前端 `services/builtInRules.ts`：

```typescript
{
  id: 'c1',
  name: '自定义规则 — 危险函数调用',
  pattern: '(dangerous_func)\\s*\\(.*?(\\$\\w+)',
  type: VulnerabilityType.CODE_EXECUTION,
  level: RiskLevel.HIGH,
  enabled: true,
  isBuiltIn: true,
}
```

### 添加新 API 端点

```python
# backend/src/routes/example.py
from fastapi import APIRouter
router = APIRouter(prefix="/api/example", tags=["example"])

@router.get("/")
async def list_items():
    return {"items": []}

# backend/src/main.py
from routes import example
app.include_router(example.router)
```

---

## 部署说明

### 配置环境变量

后端 `backend/.env`：

```env
DATABASE_URL=sqlite+aiosqlite:///./phpsentinel.db
GEMINI_API_KEY=sk-xxx      # Gemini API Key（可选）
OPENAI_API_KEY=sk-xxx      # OpenAI API Key（可选）
MOONSHOT_API_KEY=sk-xxx    # Moonshot API Key（可选）
CORS_ORIGINS=http://localhost:3000
DEBUG=false
```

### 生产构建

```bash
# 前端构建
npm run build        # 输出 → dist/

# 后端生产运行
cd backend/src
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 部署注意事项

- 静态文件由 `dist/` 提供，需配置 Nginx 反向代理
- `uploads_data/` 目录需 Web 进程有读写权限
- SQLite 不适合高并发写入场景，生产环境可切换 PostgreSQL（修改 `DATABASE_URL` 即可，SQLAlchemy 自动适配）
- AI API Key 通过环境变量注入，不暴露在前端代码中

---

## 技术栈

| 层        | 技术                                         |
| -------- | ------------------------------------------ |
| 前端框架     | React 19, TypeScript 5.8                   |
| 构建工具     | Vite 6                                     |
| 样式       | Tailwind CSS 4                             |
| 代码编辑     | Monaco Editor                              |
| 图表       | Recharts                                   |
| HTTP 客户端 | Axios                                      |
| 后端框架     | FastAPI (Python)                           |
| ORM      | SQLAlchemy 2.0 (async)                     |
| 数据库      | SQLite (aiosqlite)                         |
| AST 解析   | phply                                      |
| AI 集成    | OpenAI 兼容 API (Gemini / OpenAI / Moonshot) |
| 数据校验     | Pydantic v2                                |

---
系统截图
<img width="2864" height="1536" alt="image" src="https://github.com/user-attachments/assets/9c17d81a-33a4-44e5-99b1-b572f684c364" />
项目导入
<img width="2552" height="1308" alt="image" src="https://github.com/user-attachments/assets/855499d6-c2ad-467c-8528-6b5ba5b00bd0" />
WebSthll查杀
<img width="2552" height="1308" alt="image" src="https://github.com/user-attachments/assets/4789c34f-9850-46e8-aa7b-8056ec96f589" />
HTTP网络请求
<img width="2552" height="1308" alt="image" src="https://github.com/user-attachments/assets/f970b6b7-5d9d-43a0-b478-051f409fd75b" />
规则工厂
<img width="2552" height="1308" alt="image" src="https://github.com/user-attachments/assets/012b3e24-b8b9-46a0-9170-8acc0457f6f0" />
审计报告导出
<img width="2552" height="1308" alt="image" src="https://github.com/user-attachments/assets/70f2471b-d4a8-48af-ae8d-aa7a81b9cc38" />
审计存档
<img width="2552" height="1308" alt="image" src="https://github.com/user-attachments/assets/3d74a451-e523-40d6-b52a-afe8cd0fc5fb" />
API设置
<img width="2552" height="1308" alt="image" src="https://github.com/user-attachments/assets/69e480b0-e3eb-470d-8897-25670e9e7f71" />


