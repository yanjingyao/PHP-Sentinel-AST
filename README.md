# PHP Sentinel 技术文档

> 

---

## 目录

1. [项目概述](#1-%E9%A1%B9%E7%9B%AE%E6%A6%82%E8%BF%B0)
2. [系统架构](#2-%E7%B3%BB%E7%BB%9F%E6%9E%B6%E6%9E%84)
3. [技术栈](#3-%E6%8A%80%E6%9C%AF%E6%A0%88)
4. [核心模块详解](#4-%E6%A0%B8%E5%BF%83%E6%A8%A1%E5%9D%97%E8%AF%A6%E8%A7%A3)
5. [数据模型](#5-%E6%95%B0%E6%8D%AE%E6%A8%A1%E5%9E%8B)
6. [API 接口文档](#6-api-%E6%8E%A5%E5%8F%A3%E6%96%87%E6%A1%A3)
7. [部署指南](#7-%E9%83%A8%E7%BD%B2%E6%8C%87%E5%8D%97)
8. [开发指南](#8-%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97)
9. [安全设计](#9-%E5%AE%89%E5%85%A8%E8%AE%BE%E8%AE%A1)

---

## 1. 项目概述

### 1.1 简介

PHP Sentinel 是一个综合性的 PHP 安全审计与 WebShell 检测平台，采用**双引擎架构**设计：

- **前端引擎**: 基于正则表达式的快速扫描，提供即时反馈
- **后端引擎**: 基于 AST（抽象语法树）的深度分析，提供精确检测

### 1.2 核心能力

| 能力      | 描述                                       |
| ------- | ---------------------------------------- |
| 漏洞检测    | 支持 15 种漏洞类型，包括 SQL 注入、XSS、RCE、WebShell 等 |
| AI 辅助审计 | 集成 OpenAI 兼容 API，自动判断误报并生成 PoC           |
| 网络测试    | 内置 HTTP Repeater 和 Proxy History，支持内网穿透  |
| 规则管理    | 支持内置规则开关和自定义规则扩展                         |

### 1.3 适用场景

- PHP 代码安全审计
- WebShell 木马检测
- 漏洞复现与验证
- 安全开发培训

---

## 2. 系统架构

### 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                         前端层 (Frontend)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   Layout    │  │  Dashboard  │  │ NetworkLab  │  │  Settings   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    ASTEngine (浏览器)                          │ │
│  │  • 正则模式匹配  • 污点追踪  • 即时扫描反馈                      │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ HTTP/WebSocket
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         后端层 (Backend)                             │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    FastAPI Application                          ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            ││
│  │  │ Projects │ │  Scans   │ │Vulnerab. │ │  Files   │            ││
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            ││
│  │  │  Rules   │ │   AI     │ │ Settings │ │ Network  │            ││
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            ││
│  └─────────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    Services                                     ││
│  │  • ast_engine.py - 基于 phply 的 AST 深度分析                    ││
│  │  • ai_service.py - AI 提供商集成与代理                           ││
│  │  • file_service.py - 文件存储管理                                ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ SQLAlchemy (Async)
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         数据层 (Data)                                │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐            │
│  │   SQLite      │  │  uploads_data │  │   localStorage │           │
│  │  (主数据库)    │  │  (文件存储)    │  │  (前端配置)    │           │
│  └───────────────┘  └───────────────┘  └───────────────┘            │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 双引擎扫描架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                        双引擎检测流程                                 │
└─────────────────────────────────────────────────────────────────────┘

用户上传 ZIP/文件夹
         │
         ▼
┌─────────────────────────┐
│  1. 前端引擎 (即时反馈)  │
│  • 正则模式匹配          │
│  • 污点数据流追踪         │
│  • 15+ 内置规则          │
└─────────────────────────┘
         │
         ▼
┌─────────────────────────┐
│  2. 持久化到后端         │
│  • 文件存储             │
│  • 漏洞记录             │
│  • 扫描任务状态          │
└─────────────────────────┘
         │
         ▼
┌─────────────────────────┐
│  3. 后端引擎 (深度分析)  │
│  • PHP AST 解析         │
│  • Source/Sink 分析      │
│  • 净化函数检测          │
│  • 正则回退             │
└─────────────────────────┘
         │
         ▼
┌─────────────────────────┐
│  4. AI 辅助审计          │
│  • 误报判断             │
│  • PoC 生成             │
│  • 载荷提取             │
└─────────────────────────┘
```

---

## 3. 技术栈

### 3.1 前端技术栈

| 技术            | 版本  | 用途       |
| ------------- | --- | -------- |
| React         | 19  | UI 框架    |
| TypeScript    | 5.8 | 类型安全     |
| Vite          | 6   | 构建工具     |
| Tailwind CSS  | v4  | 样式框架     |
| Monaco Editor | -   | 代码编辑     |
| Axios         | -   | HTTP 客户端 |
| Recharts      | -   | 数据可视化    |

### 3.2 后端技术栈

| 技术         | 版本    | 用途            |
| ---------- | ----- | ------------- |
| Python     | 3.11+ | 运行时           |
| FastAPI    | -     | Web 框架        |
| SQLAlchemy | 2.0   | ORM (异步)      |
| phply      | -     | PHP AST 解析    |
| httpx      | -     | HTTP 客户端 (异步) |
| Pydantic   | -     | 数据验证          |
| SQLite     | -     | 数据库           |

### 3.3 AI 集成

| 提供商            | 支持状态 | 说明               |
| -------------- | ---- | ---------------- |
| 自定义 OpenAI API | ✅ 推荐 | 支持任意 OpenAI 兼容端点 |

---

## 4. 核心模块详解

### 4.1 前端 AST 引擎 (`services/astEngine.ts`)

#### 4.1.1 内置规则分类

| 规则 ID   | 名称                 | 漏洞类型          | 风险等级  |
| ------- | ------------------ | ------------- | ----- |
| b1a/b1b | SQL 注入             | SQL 注入        | 严重    |
| b2      | XSS                | 跨站脚本          | 高危    |
| b3      | 代码执行 (RCE)         | 远程代码执行        | 严重    |
| b4      | 文件包含 (LFI/RFI)     | 文件包含          | 高危    |
| b5      | 不安全的文件上传           | 文件上传          | 严重    |
| b6      | 任意文件操作             | 路径穿越          | 高危    |
| b7      | SSRF (Curl/Stream) | SSRF          | 高危    |
| b8      | 反序列化               | 反序列化          | 严重    |
| b9      | 敏感信息泄露             | 敏感调用          | 提示    |
| m1-m4   | 中危规则               | 弱加密/头部注入/LDAP | 中危    |
| l1-l4   | 低危规则               | 弱哈希/硬编码密码     | 低危    |
| w1-w5   | WebShell 专项        | WebShell      | 严重/高危 |

#### 4.1.2 污点追踪机制

```typescript
// 污点源 (Source)
SOURCE_SUPERGLOBALS = /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[['"].*?['"]\]/g

// 污点传播流程
用户输入 ($_GET['id']) 
    → 变量赋值 ($id = $_GET['id'])
    → 污点传播 ($sql = "SELECT * FROM users WHERE id = $id")
    → 危险函数调用 (mysql_query($sql))
    → 漏洞报告
```

#### 4.1.3 扫描流程

```typescript
async scanFile(fileName: string, code: string, isWebshellMode: boolean): Promise<Vulnerability[]> {
  // 1. 获取启用的规则（内置 + 自定义）
  const effectiveRules = this.getEffectiveRules();

  // 2. 根据模式过滤规则
  const activeRules = effectiveRules.filter(r => {
    const isWebshellRule = r.type === VulnerabilityType.WEBSHELL;
    return isWebshellMode ? isWebshellRule : !isWebshellRule;
  });

  // 3. 逐行扫描
  for (let i = 0; i < lines.length; i++) {
    // 4. 污点追踪：识别用户输入源
    // 5. 规则匹配：检测危险函数调用
    // 6. 生成漏洞报告
  }
}
```

### 4.2 后端 AST 引擎 (`backend/src/services/ast_engine.py`)

#### 4.2.1 核心组件

| 组件          | 描述                                                 |
| ----------- | -------------------------------------------------- |
| `Source`    | 用户可控输入源（`$_GET`, `$_POST`, `$_COOKIE` 等）           |
| `Sink`      | 危险函数调用点（`mysql_query`, `eval`, `system` 等）         |
| `Sanitizer` | 净化函数（`intval`, `htmlspecialchars`, `addslashes` 等） |
| `Taint`     | 污点数据流追踪                                            |

#### 4.2.2 Sink 定义

```python
SINKS: Dict[str, SinkSpec] = {
    # SQL 注入
    "mysql_query": SinkSpec(VulnerabilityType.SQL_INJECTION, RiskLevel.CRITICAL),
    "mysqli_query": SinkSpec(VulnerabilityType.SQL_INJECTION, RiskLevel.CRITICAL),

    # 代码执行
    "eval": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL),
    "system": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL),
    "exec": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL),

    # 文件包含
    "include": SinkSpec(VulnerabilityType.FILE_INCLUSION, RiskLevel.HIGH),
    "require": SinkSpec(VulnerabilityType.FILE_INCLUSION, RiskLevel.HIGH),

    # ... 更多定义
}
```

#### 4.2.3 净化函数

```python
SANITIZERS = {
    "intval",           # 整数转换
    "floatval",         # 浮点转换
    "htmlspecialchars", # HTML 实体编码
    "htmlentities",     # HTML 实体编码
    "strip_tags",       # 去除 HTML 标签
    "mysqli_real_escape_string",  # SQL 转义
    "addslashes",       # 添加反斜杠
}
```

### 4.3 AI 服务集成

#### 4.3.1 架构设计

```
前端 (AIService)
    │
    ├── 配置读取 (localStorage)
    │
    └── 后端代理调用 (aiProxyApi)
            │
            ▼
    ┌──────────────────┐
    │  /api/ai/review  │  漏洞审计
    │  /api/ai/chat    │  对话交互
    └──────────────────┘
            │
            ▼
    ┌──────────────────┐
    │  ai_service.py   │
    │  • 配置管理       │
    │  • 提示词构建     │
    │  • API 调用      │
    └──────────────────┘
            │
            ▼
    ┌──────────────────┐
    │  AI 提供商       │
    │  (OpenAI 兼容)   │
    └──────────────────┘
```

#### 4.3.2 审计提示词模板

```python
SYSTEM_PROMPT = """你是一位经验丰富的 PHP 安全审计专家。
请分析以下代码片段中的安全漏洞：

漏洞类型: {vuln_type}
风险等级: {level}
文件: {file_name}
行号: {line}
代码片段:
```php
{snippet}
```

请判断这是否为误报，并给出详细分析。如果是真实漏洞，请提供：

1. 漏洞原理说明

2. 利用方式

3. 修复建议

4. PoC (curl/httpie 格式)
   """

### 4.4 网络实验室 (`components/NetworkLab.tsx`)

#### 4.4.1 功能特性

- **HTTP Repeater**: 自定义构造和发送 HTTP 请求
- **Proxy History**: 请求历史记录与回放
- **内网穿透**: 支持访问 `127.0.0.1` 等内网地址
- **CORS 绕过**: 通过后端代理解决跨域问题

#### 4.4.2 请求流程

```
用户编辑请求
    │
    ▼
┌─────────────────────┐
│  解析请求行和 Headers │
│  • Method 提取       │
│  • URL 构造          │
│  • Header 解析       │
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  后端代理转发        │
│  POST /api/network/proxy
│  • 目标 URL         │
│  • Headers          │
│  • Body             │
└─────────────────────┘
    │
    ▼
目标服务器响应
    │
    ▼
响应格式化显示
```

---

## 5. 数据模型

### 5.1 数据库 ER 图

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│   Project    │       │     Scan     │       │Vulnerability │
├──────────────┤       ├──────────────┤       ├──────────────┤
│ id (PK)      │◄──────┤ id (PK)      │◄──────┤ id (PK)      │
│ name         │       │ project_id   │       │ scan_id (FK) │
│ description  │       │ status       │       │ project_id   │
│ created_at   │       │ total_files  │       │ file_id      │
│ updated_at   │       │ scanned_files│       │ type         │
└──────────────┘       │ is_webshell  │       │ level        │
        │              │ created_at   │       │ line         │
        │              └──────────────┘       │ file_name    │
        │                                     │ snippet      │
        │                                     │ source       │
        │                                     │ sink         │
        │                                     │ ai_assessment│
        │                                     │ chat_history │
        │                                     └──────────────┘
        │
        ▼
┌──────────────┐
│     File     │
├──────────────┤
│ id (PK)      │
│ project_id   │
│ name         │
│ path         │
│ content      │
│ size         │
└──────────────┘
```

### 5.2 核心实体

#### 5.2.1 Project (项目)

| 字段          | 类型          | 说明   |
| ----------- | ----------- | ---- |
| id          | String (PK) | UUID |
| name        | String      | 项目名称 |
| description | Text        | 项目描述 |
| created_at  | DateTime    | 创建时间 |
| updated_at  | DateTime    | 更新时间 |

#### 5.2.2 Scan (扫描任务)

| 字段               | 类型          | 说明                                   |
| ---------------- | ----------- | ------------------------------------ |
| id               | String (PK) | UUID                                 |
| project_id       | String (FK) | 关联项目                                 |
| status           | String      | 状态: pending/running/completed/failed |
| total_files      | Integer     | 总文件数                                 |
| scanned_files    | Integer     | 已扫描文件数                               |
| is_webshell_mode | Boolean     | WebShell 扫描模式                        |

#### 5.2.3 Vulnerability (漏洞)

| 字段            | 类型          | 说明      |
| ------------- | ----------- | ------- |
| id            | String (PK) | UUID    |
| scan_id       | String (FK) | 关联扫描    |
| type          | String      | 漏洞类型    |
| level         | String      | 风险等级    |
| line          | Integer     | 行号      |
| file_name     | String      | 文件名     |
| snippet       | Text        | 代码片段    |
| ai_assessment | JSON        | AI 审计结果 |
| chat_history  | JSON        | 对话历史    |

### 5.3 TypeScript 类型定义

```typescript
// 漏洞类型枚举
export const VulnerabilityType = {
  SQL_INJECTION: 'SQL 注入',
  XSS: '跨站脚本攻击 (XSS)',
  CODE_EXECUTION: '远程代码执行 (RCE)',
  FILE_INCLUSION: '文件包含 (LFI/RFI)',
  SSRF: '服务端请求伪造 (SSRF)',
  DESERIALIZATION: '不安全的反序列化',
  PATH_TRAVERSAL: '路径穿越/任意文件操作',
  FILE_UPLOAD: '不安全的文件上传',
  WEAK_CRYPTO: '弱加密/哈希算法',
  HEADER_INJECTION: 'HTTP 头部注入',
  LDAP_INJECTION: 'LDAP 注入',
  WEBSHELL: 'Webshell 恶意后门',
  CUSTOM: '自定义规则'
} as const;

// 风险等级枚举
export const RiskLevel = {
  CRITICAL: '严重',
  HIGH: '高危',
  MEDIUM: '中危',
  LOW: '低危',
  INFO: '提示'
} as const;
```

---

## 6. API 接口文档

### 6.1 项目管理

| 方法     | 端点                   | 描述     |
| ------ | -------------------- | ------ |
| GET    | `/api/projects`      | 获取项目列表 |
| POST   | `/api/projects`      | 创建项目   |
| GET    | `/api/projects/{id}` | 获取项目详情 |
| PUT    | `/api/projects/{id}` | 更新项目   |
| DELETE | `/api/projects/{id}` | 删除项目   |

### 6.2 文件管理

| 方法     | 端点                           | 描述       |
| ------ | ---------------------------- | -------- |
| GET    | `/api/files?project_id={id}` | 获取项目文件列表 |
| POST   | `/api/files`                 | 上传文件     |
| GET    | `/api/files/{id}`            | 获取文件内容   |
| DELETE | `/api/files/{id}`            | 删除文件     |

### 6.3 扫描任务

| 方法     | 端点                           | 描述             |
| ------ | ---------------------------- | -------------- |
| GET    | `/api/scans?project_id={id}` | 获取扫描列表         |
| POST   | `/api/scans`                 | 创建扫描任务         |
| GET    | `/api/scans/{id}`            | 获取扫描详情         |
| DELETE | `/api/scans/{id}`            | 删除扫描记录         |
| WS     | `/api/scans/{id}/ws`         | WebSocket 进度推送 |

### 6.4 漏洞管理

| 方法     | 端点                                  | 描述      |
| ------ | ----------------------------------- | ------- |
| GET    | `/api/vulnerabilities?scan_id={id}` | 获取漏洞列表  |
| POST   | `/api/vulnerabilities/batch`        | 批量创建漏洞  |
| POST   | `/api/vulnerabilities/{id}/review`  | AI 审计漏洞 |
| POST   | `/api/vulnerabilities/{id}/chat`    | AI 对话   |
| DELETE | `/api/vulnerabilities/{id}`         | 删除漏洞    |

### 6.5 AI 代理

| 方法   | 端点               | 描述     |
| ---- | ---------------- | ------ |
| POST | `/api/ai/review` | 代理审计请求 |
| POST | `/api/ai/chat`   | 代理对话请求 |

### 6.6 网络代理

| 方法     | 端点                   | 描述         |
| ------ | -------------------- | ---------- |
| POST   | `/api/network/proxy` | 代理 HTTP 请求 |
| GET    | `/api/network/logs`  | 获取请求历史     |
| POST   | `/api/network/logs`  | 保存请求记录     |
| DELETE | `/api/network/logs`  | 清空历史       |

### 6.7 规则管理

| 方法     | 端点                | 描述      |
| ------ | ----------------- | ------- |
| GET    | `/api/rules`      | 获取规则列表  |
| POST   | `/api/rules`      | 创建自定义规则 |
| PUT    | `/api/rules/{id}` | 更新规则    |
| DELETE | `/api/rules/{id}` | 删除规则    |

---

## 7. 部署指南

### 7.1 环境要求

| 组件      | 版本要求  |
| ------- | ----- |
| Node.js | 18+   |
| Python  | 3.11+ |
| SQLite  | 3.35+ |

### 7.2 安装步骤

#### 7.2.1 前端部署

```bash
# 1. 安装依赖
npm install --legacy-peer-deps

# 2. 开发模式启动
npm run dev

# 3. 生产构建
npm run build

# 4. 预览生产构建
npm run preview
```

#### 7.2.2 后端部署

```bash
# 1. 进入后端目录
cd backend

# 2. 安装依赖
pip install -r requirements.txt

# 3. 启动开发服务器
cd src && uvicorn main:app --reload --port 8000

# 4. 生产部署（使用 Gunicorn）
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000
```

### 7.3 配置环境变量

#### 后端 `.env`

```env
# 数据库
DATABASE_URL=sqlite:///./phpsentinel.db

# AI 配置（可选）
OPENAI_API_KEY=your_api_key

# CORS 配置
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# 调试模式
DEBUG=true

# 上传目录
UPLOAD_DIR=uploads_data
```

---

## 8. 开发指南

### 8.1 项目结构

```
php-sentinel/
├── index.html              # HTML 入口
├── index.tsx               # React 入口
├── App.tsx                 # 主应用组件
├── types.ts                # 全局类型定义
├── components/             # UI 组件
│   ├── Layout.tsx          # 布局组件
│   ├── Dashboard.tsx       # 仪表板
│   ├── NetworkLab.tsx      # 网络实验室
│   ├── Settings.tsx        # 设置页面
│   └── ...
├── services/               # 前端业务逻辑
│   ├── astEngine.ts        # 前端扫描引擎
│   ├── aiService.ts        # AI 服务封装
│   └── dbService.ts        # 数据持久化
├── frontend/src/api/       # API 客户端
│   ├── client.ts           # Axios 配置
│   ├── projects.ts         # 项目 API
│   ├── scans.ts            # 扫描 API
│   └── ...
└── backend/
    ├── requirements.txt    # Python 依赖
    └── src/
        ├── main.py         # FastAPI 入口
        ├── models.py       # 数据库模型
        ├── schemas.py      # Pydantic 模型
        ├── routes/         # API 路由
        └── services/       # 业务逻辑
```

### 8.2 添加新漏洞类型

#### 8.2.1 前端规则

```typescript
// services/astEngine.ts
static BUILT_IN_RULES: Rule[] = [
  // 添加新规则
  { 
    id: 'x1', 
    name: '新的漏洞类型', 
    pattern: 'dangerous_function\s*\(\s*\$(\w+)', 
    type: VulnerabilityType.CUSTOM, 
    level: RiskLevel.HIGH, 
    enabled: true, 
    isBuiltIn: true 
  },
];
```

#### 8.2.2 后端规则

```python
# backend/src/services/ast_engine.py
SINKS: Dict[str, SinkSpec] = {
    "dangerous_function": SinkSpec(
        VulnerabilityType.CUSTOM, 
        RiskLevel.HIGH
    ),
}
```

### 8.3 添加新 API 端点

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

### 8.4 调试技巧

| 问题               | 解决方案                    |
| ---------------- | ----------------------- |
| 后端导入错误           | 确保从 `backend/src` 目录运行  |
| Vite HMR 问题      | 检查 `uploads_data/` 目录权限 |
| Monaco Worker 错误 | 检查 CDN 连接和 CSP 配置       |
| 数据库锁定            | 关闭并发连接，SQLite 不支持高并发写入  |

---

## 9. 安全设计

### 9.1 文件上传安全

- **类型过滤**: 仅接受文本文件（PHP, JS, HTML 等）
- **存储隔离**: 文件存储在项目根目录外的 `uploads_data/`
- **路径遍历防护**: 上传处理器中验证文件路径

### 9.2 API 安全

- **CORS 配置**: 限制允许的源
- **AI 密钥保护**: API 密钥存储在服务端，不暴露给前端
- **请求验证**: Pydantic 模型验证所有输入

### 9.3 网络代理安全

- **非法 Header 过滤**: 过滤包含空格的非法 header names
- **危险 Header 移除**: 自动移除 `Host`, `Content-Length`, `Connection`
- **超时控制**: 默认 10 秒超时，防止资源耗尽

### 9.4 AI 安全

- **JSON 验证**: AI 响应严格 JSON 格式验证
- **错误处理**: 超时、速率限制和 API 故障处理
- **用户确认**: 执行生成的 PoC 前需要用户确认

---

## 附录

### A. 漏洞类型对照表

| 类型       | 英文名                         | 严重程度 |
| -------- | --------------------------- | ---- |
| SQL 注入   | SQL Injection               | 严重   |
| XSS      | Cross-Site Scripting        | 高危   |
| RCE      | Remote Code Execution       | 严重   |
| LFI/RFI  | File Inclusion              | 高危   |
| SSRF     | Server-Side Request Forgery | 高危   |
| 反序列化     | Deserialization             | 严重   |
| WebShell | WebShell Backdoor           | 严重   |

### B. 风险等级颜色

| 等级  | 颜色代码    | 说明     |
| --- | ------- | ------ |
| 严重  | #e11d48 | 立即利用风险 |
| 高危  | #ea580c | 严重安全风险 |
| 中危  | #ca8a04 | 中等风险   |
| 低危  | #2563eb | 轻微安全问题 |
| 提示  | #64748b | 信息性发现  |

---
