# 运行手册

启动前请先完成 [安装准备（INSTALL.md）](./INSTALL.md)。
本工作台采用**单端口**部署：Flask 同时提供 API 与前端页面，默认 `http://localhost:5000`。

---

## 1. 一键启动（Windows 推荐）

在项目根目录双击或运行：

```bat
start.bat
```

脚本会依次：

1. 检查 Python；若需构建再检查 Node.js（缺 Node 会明确报错，而不是白屏）；
2. 若未装过后端依赖 → `pip install -r backend\requirements.txt`；
3. 若 `frontend\node_modules` 不存在 → `npm install`；
4. **前端构建（自动判断）**：脚本比对前端源码与已构建产物的时间——**源码有更新（或首次运行）才重建，否则跳过**；
5. 启动后端 `python backend\app.py --serve-frontend`，并自动打开浏览器。

> **你只需要双击 `start.bat`**，无需关心改了什么、也无需带参数——是否重建由脚本自动决定。
> （`start.bat --rebuild` 为可选的强制重建开关，正常使用用不到。）

---

## 2. 手动启动（跨平台 / 需要精细控制）

```bash
# 1) 首次或前端代码有改动时，构建前端
cd frontend
npm run build
cd ..

# 2) 启动后端（托管前端 + API，单端口）
python backend/app.py --serve-frontend
```

- 只要 `frontend/dist/index.html` 已存在，第 1 步可跳过。
- 后端启动参数 `--serve-frontend` 表示由 Flask 托管前端静态产物。

---

## 3. 访问地址

| 场景 | 地址 |
|------|------|
| 本机访问 | http://localhost:5000 |
| **局域网其他机器访问** | http://<本机IP>:5000 |

> 后端默认监听 `0.0.0.0`（见「环境变量」），因此**同网段其他主机可直接访问**。
> 用 `ipconfig` 查本机 IP；如无法访问，检查 Windows 防火墙是否放行 5000 端口。

---

## 4. 环境变量（可选）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `FLASK_HOST` | `0.0.0.0` | 监听地址；设为 `127.0.0.1` 则仅本机可访问 |
| `FLASK_PORT` | `5000` | 端口；被占用时改这里 |
| `FLASK_DEBUG` | `False` | 调试模式，生产保持 False |

示例（改端口后启动）：

```bat
set FLASK_PORT=8080
python backend\app.py --serve-frontend
```

---

## 5. 停止服务

在运行窗口按 **`Ctrl + C`** 即可正常终止。

---

## 6. 更新代码后如何生效

| 改动位置 | 需要的操作 |
|----------|-----------|
| 前端（`frontend/src/**`） | 直接重跑 `start.bat`（会自动检测到改动并重建），然后浏览器**硬刷新** `Ctrl+Shift+R`（产物带哈希，避免缓存） |
| 后端（`backend/**`） | **重启后端进程**（服务以 `use_reloader=False` 运行，不会热重载） |

---

## 7. 数据与文件位置

| 内容 | 路径 | 说明 |
|------|------|------|
| 业务数据库 | `backend/data/`（SQLite） | 首次运行自动创建 |
| 上传附件 / 截图 | `backend/uploads/` | 告警截图、证据文件 |
| 前端构建产物 | `frontend/dist/` | Flask 托管的静态页面 |

> 备份/迁移数据：拷贝 `backend/data/` 与 `backend/uploads/` 即可。

---

## 8. OCR 识别功能（可选）

- 若已安装 `rapidocr-onnxruntime`（见 INSTALL.md 3.6），详情页可用「**从截图识别字段**」，上报页粘贴文本可「**从文本识别字段**」，自动提取 IP / 域名 / Hash / 命令行等预填「告警详情」，由研判员核对后写入。
- **未安装时**：点击会提示安装指引，其余功能完全不受影响（优雅降级）。
- 安装后需**重启后端**才生效。

---

## 9. 故障排查

| 现象 | 排查方向 |
|------|----------|
| 页面白屏 | 前端未构建 → 跑 `npm run build`；或浏览器缓存 → 硬刷新 `Ctrl+Shift+R` |
| 接口报错 / `HTTP 405` / `fetch failed` | 后端未启动或已崩溃 → 查看运行窗口日志，重启 `python backend\app.py --serve-frontend` |
| 端口 5000 被占用 | 设 `FLASK_PORT` 换端口（第 4 节） |
| 局域网访问不了 | 确认 `FLASK_HOST=0.0.0.0`；放行防火墙 5000 端口；用对本机 IP |
| 「从截图/文本识别字段」不可用 | 未装 OCR 引擎 → 按 INSTALL.md 3.6 安装并重启后端 |
| 改了后端代码不生效 | 服务不热重载，需手动重启进程 |

---

相关：安装准备见 [INSTALL.md](./INSTALL.md)；研判处理闭环说明见 [incident-triage-closed-loop.md](./incident-triage-closed-loop.md)。
