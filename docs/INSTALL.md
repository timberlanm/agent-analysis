# 安装准备文档

本文件说明在一台**新机器**上运行「研判分析工作台」之前需要准备的运行环境与依赖。
准备完成后，请按 [运行手册（RUN.md）](./RUN.md) 启动。

> 一句话：装好 **Python**、**Node.js** 两个运行时及各自依赖即可。

---

## 1. 运行环境要求

| 组件 | 版本要求 | 说明 |
|------|----------|------|
| 操作系统 | Windows 10/11 | 提供 `start.bat` 一键脚本；Linux/macOS 可手动运行（见 RUN.md） |
| Python | **3.8+**（建议 3.10–3.12） | 后端 Flask 服务 |
| Node.js | **16+**（建议 18 LTS） | 前端 Vue3 + Vite4 构建，需自带 npm |
| 磁盘 | ≥ 1 GB 空闲 | 依赖 + 构建产物 |
| 网络 | 安装阶段需联网 | 拉取 pip / npm 依赖；**运行阶段可离线** |

---

## 2. 组成与依赖

- **后端**（`backend/`）：Flask + flask-cors + pyyaml，数据存 SQLite（首次运行自动创建）。
- **前端**（`frontend/`）：Vue 3 + Element Plus + Vite，构建为静态产物 `frontend/dist/`，由 Flask 单端口托管。

---

## 3. 安装步骤

### 3.1 安装 Python

1. 到 https://www.python.org/downloads/ 下载 3.10+ 安装包。
2. 安装时**务必勾选 “Add Python to PATH”**。
3. 验证：

   ```bat
   python --version
   pip --version
   ```

### 3.2 安装 Node.js

1. 到 https://nodejs.org/ 下载 **18 LTS** 安装包（自带 npm）。
2. 验证：

   ```bat
   node -v
   npm -v
   ```

### 3.3 配置国内镜像（国内网络强烈建议）

直连官方源常出现超时/握手失败，配镜像后稳定很多：

```bat
:: npm 镜像
npm config set registry https://registry.npmmirror.com

:: pip 镜像（写入全局配置，之后所有 pip 命令生效）
pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/
pip config set global.trusted-host mirrors.aliyun.com
```

### 3.4 安装后端依赖

```bat
pip install -r backend\requirements.txt
```

### 3.5 安装前端依赖

```bat
cd frontend
npm install
cd ..
```

## 4. 一键 vs 手动

- **一键（Windows）**：完成 3.1–3.3 后，直接运行 `start.bat` 即可自动完成 3.4/3.5 的依赖安装与前端构建并启动。见 RUN.md。
- **手动**：按 3.4–3.5 逐步执行，再按 RUN.md「手动启动」运行。

---

## 5. 离线 / 内网部署

目标机无外网时，任选其一：

1. **预置构建产物**：在有网的机器上 `cd frontend && npm run build`，把整个 `frontend/dist/` 一起拷到目标机——目标机**无需安装 Node、也无需 npm install/build**，只装 Python + 后端依赖即可。
2. **预下载依赖**：有网机器 `pip download -r backend/requirements.txt -d wheels/`，拷到目标机后 `pip install --no-index --find-links wheels -r backend/requirements.txt`。

---

## 6. 常见安装问题

| 现象 | 原因 / 解决 |
|------|------------|
| `pip install` 卡住 / ReadTimeout | 官方源慢，改用阿里云镜像（3.3） |
| Tsinghua 镜像 SSL 握手失败 | 换阿里云镜像并加 `--trusted-host` |
| `npm install` 很慢 / 失败 | 设置 npmmirror registry（3.3） |
| `'python' / 'npm' 不是内部或外部命令` | 未加入 PATH，重装并勾选 Add to PATH，或重开终端 |
| pip 装到了别的 Python | 用 `python -m pip install ...` 明确指定当前解释器 |

---

安装准备就绪后 → 请继续阅读 [运行手册（RUN.md）](./RUN.md)。
