# 研判分析工作台 (Incident Analysis)

安全告警研判分析平台，支持多源告警录入、多维度筛选、详情编辑、截图附件管理、关联分析、审计日志、JSON/Markdown 导出等功能。

## 功能特性

- **告警列表**：按关键词、来源、状态、严重程度、研判结论等多条件筛选，展示攻击IP/被攻击IP/上报人/研判人等信息
- **告警录入**：支持 EDR/HIDS/NDR/WAF/SIEM 等多种安全设备模板，完整字段表单
- **告警详情**：编辑告警信息、管理截图和附件、添加研判备注、设置研判结论（误报/确认攻击/忽略等）和处置状态
- **批量操作**：批量关闭、分配研判责任人
- **数据导出**：JSON / Markdown 格式导出单条告警，CSV 导出运营统计
- **关联分析**：基于 IP/Hash/域名/URL 等实体自动发现关联告警
- **审计日志**：完整记录所有告警操作历史
- **SLA 管理**：按严重等级自动计算响应和处置时限

## 技术栈

| 层       | 技术                        |
| -------- | --------------------------- |
| 后端 API | Python 3.8+ / Flask 2.3     |
| 数据库   | SQLite                      |
| 前端     | Vue 3.3 / Element Plus 2.3  |
| 构建     | Vite 4.4                    |
| 部署     | Flask 单端口托管 API + 静态文件 |

## 快速开始

### 环境要求

- Python 3.8+
- Node.js 18+（如需前端开发）

### 安装

```bash
# 1. 克隆仓库
git clone https://github.com/YOUR_USERNAME/incident-analysis.git
cd incident-analysis

# 2. 安装 Python 依赖
pip install -r backend/requirements.txt

# 3. 安装前端依赖（可选，仅开发时需要）
cd frontend && npm install && cd ..
```

### 启动

**Windows（一键启动）：**
```
双击 start.bat
```

**手动启动：**

```bash
# 仅 API（开发模式，前端用 npm run dev）
python backend/app.py

# API + 前端（生产模式，访问 http://localhost:5000）
python backend/app.py --serve-frontend
```

**前端开发模式：**
```bash
cd frontend
npm run dev          # 访问 http://localhost:3000
```

### 生产部署

```bash
# 构建前端
cd frontend && npm run build && cd ..

# 启动生产服务
python backend/app.py --serve-frontend
```

## 项目结构

```
incident-analysis/
├── backend/
│   ├── api/
│   │   ├── __init__.py
│   │   └── incident.py          # API 蓝图（20+ 端点）
│   ├── services/
│   │   ├── __init__.py
│   │   └── incident_service.py  # 服务层（SQLite 操作）
│   ├── data/                    # 运行时生成（SQLite 数据库）
│   ├── uploads/                 # 运行时生成（附件存储）
│   ├── app.py                   # Flask 主入口
│   ├── config.py                # 配置
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   └── index.js         # API 客户端
│   │   ├── router/
│   │   │   └── index.js         # Vue Router
│   │   ├── views/
│   │   │   └── Incident.vue     # 研判分析主页面
│   │   ├── App.vue              # 根布局
│   │   └── main.js              # 入口
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── .gitignore
└── start.bat
```

## License

MIT
