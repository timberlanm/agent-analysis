# Ubuntu 22.04 首次安装

`bootstrap.sh` 只用于全新 Ubuntu 22.04 环境的首次安装。Windows 开发机提前构建
`frontend/dist`；Ubuntu 不需要 Node.js。

脚本支持三种首次安装方式：

- 本地项目目录 + 可访问软件源：默认方式，不连接 GitHub；
- GitHub + 可访问软件源：显式设置 `SOURCE_MODE=github`；
- 本地项目目录 + 完全断网：设置 `OFFLINE_MODE=1`，并提供本地 wheelhouse，
  系统依赖则提前安装或提供完整 `.deb` 集合。

## 部署用户和维护目录

部署用户不固定为 `hacker`。通过某个普通登录用户执行 `sudo bash` 时，脚本从
`SUDO_USER` 自动识别该用户，并把应用放在其 Home 目录：

```text
/home/<部署用户>/soc-workbench/
├── current -> releases/<release>/           安装成功后的正式入口
├── releases/
│   └── <release>/                           代码和该版本的 venv
├── config/
│   ├── soc-workbench.env                    服务运行配置
│   └── soc-workbench.migration.env          数据库初始化配置
├── runtime/
│   ├── data/                                Flask 密钥和种子导入报告
│   ├── uploads/incident/                    告警图片、附件和附件日志
│   └── logs/                                应用文件日志
├── installer/
│   ├── state.json                           安装阶段和来源状态
│   ├── bootstrap.log                        完整安装日志
│   ├── bootstrap-last-failure.log           最近一次失败摘要
│   └── health.json                          最近一次健康检查结果
└── backups/                                 后续数据库升级备份
```

PostgreSQL 数据目录和 systemd journal 仍由操作系统管理。唯一位于该目录之外的应用
文件是：

```text
/etc/systemd/system/soc-workbench.service
```

如果直接从 root shell 执行，无法获得 `SUDO_USER`，必须明确指定普通部署用户：

```bash
DEPLOY_USER=operator bash deploy/linux/bootstrap.sh
```

脚本会验证该用户存在，且安装根目录必须位于其 Home 目录内。

## 公共前置条件

- Ubuntu 22.04；
- PostgreSQL 已安装并运行；
- PostgreSQL 监听本机 `127.0.0.1:5432`；
- 项目中已有 Windows 构建生成的 `frontend/dist/index.html`；
- 项目中包含测试数据库 `backend/data/analysis_store.db`；
- 当前主机不存在旧的 `/opt/soc-workbench` 部署或同名正式服务。

不要把生成后的配置文件和密码提交到代码仓库。

## 方式一：本地项目目录安装（默认）

先用 SCP、内网 Git、共享目录、移动介质或制品系统，把完整项目复制到 Ubuntu，例如：

```bash
cd /home/operator/agent-analysis-package
sudo bash deploy/linux/bootstrap.sh
```

默认值为：

```text
SOURCE_MODE=local
LOCAL_SOURCE_DIR=执行 bootstrap.sh 的项目根目录
OFFLINE_MODE=0
```

本地目录保留 `.git` 时，脚本固定安装当前提交并要求 Git 工作区干净；
`deploy/offline` 下被忽略的离线依赖包不影响检查。本地目录不含 `.git` 时，脚本按
项目文件内容计算 release 摘要并复制代码。两种方式都不访问 GitHub。

也可以显式指定另一个项目目录：

```bash
sudo env \
  SOURCE_MODE=local \
  LOCAL_SOURCE_DIR=/mnt/releases/agent-analysis \
  bash deploy/linux/bootstrap.sh
```

## 方式二：从 GitHub 安装

仅在主机能够访问 GitHub 时使用：

```bash
cd /home/operator/agent-analysis-bootstrap
sudo env \
  SOURCE_MODE=github \
  REPO_URL=https://github.com/timberlanm/agent-analysis.git \
  BRANCH=master \
  bash deploy/linux/bootstrap.sh
```

脚本解析一次远端提交并写入状态文件；发生失败后续装仍使用这个固定提交。

## 方式三：完全断网安装

### 1. 准备本地项目

把完整项目目录传入目标 Ubuntu。不要使用 Windows 的 Python 虚拟环境或 Windows
wheel；Python 离线包必须与目标机的 Ubuntu 版本、CPU 架构和 Python 版本兼容。

### 2. 准备 Python wheelhouse

建议在一台可联网、同为 Ubuntu 22.04、相同 CPU 架构和 Python 版本的机器上执行：

```bash
cd /path/to/agent-analysis
mkdir -p deploy/offline/wheels
python3 -m pip download \
  --only-binary=:all: \
  --dest deploy/offline/wheels \
  pip setuptools wheel \
  -r backend/requirements-linux.txt \
  -r backend/requirements-dev.txt
```

命令必须成功完成。随后把 `deploy/offline/wheels` 连同项目一起复制到断网主机。

### 3. 准备系统依赖

推荐先在离线 Ubuntu 镜像或标准模板中安装 PostgreSQL，以及脚本需要的
Python、venv、ACL、rsync、curl、OpenSSL、CA 证书和运行库。也可以把目标 Ubuntu
版本及架构对应的完整 `.deb` 依赖集合放到：

```text
deploy/offline/debs/
```

脚本只会使用该目录已有的 `.deb`，不会下载缺失依赖；集合不完整时会在系统依赖阶段
停止并记录原因。

### 4. 执行断网安装

```bash
cd /home/operator/agent-analysis-package
sudo env \
  SOURCE_MODE=local \
  OFFLINE_MODE=1 \
  LOCAL_SOURCE_DIR="$PWD" \
  WHEELHOUSE="$PWD/deploy/offline/wheels" \
  OFFLINE_DEB_DIR="$PWD/deploy/offline/debs" \
  bash deploy/linux/bootstrap.sh
```

断网模式不会执行 `apt-get update`、GitHub 请求或 PyPI 请求。pip 被强制使用：

```text
--no-index --find-links <wheelhouse>
```

## 第一次执行：生成配置模板

第一次执行会创建：

```text
/home/<部署用户>/soc-workbench/config/soc-workbench.env
/home/<部署用户>/soc-workbench/config/soc-workbench.migration.env
```

然后脚本按设计停止，要求填写数据库密码。以部署用户 `operator` 为例：

```bash
sudo nano /home/operator/soc-workbench/config/soc-workbench.env
sudo nano /home/operator/soc-workbench/config/soc-workbench.migration.env
```

应用和数据库在同一台 Ubuntu 时，数据库连接使用 `127.0.0.1:5432`。

## 第二次执行和失败续装

填写配置后，重新执行脚本即可。脚本会从状态文件恢复首次选择的 `SOURCE_MODE`、
`OFFLINE_MODE`、`LOCAL_SOURCE_DIR`、wheelhouse 和本地 `.deb` 路径；如果再次显式
传入这些参数，其值必须与首次执行一致。

脚本按以下阶段执行：

1. 检查 Ubuntu、部署用户和现有部署；
2. 安装或验证系统依赖并创建 Home 目录布局；
3. 创建和验证本地配置；
4. 固定来源版本并准备 release；
5. 创建或复用 Python venv；
6. 创建或验证 PostgreSQL 角色、数据库、Schema 和种子数据；
7. 同步并校验告警图片、附件和附件日志；
8. 渲染并安装 systemd 服务；
9. 激活 release，启动服务并等待最多 60 秒；
10. 健康检查成功后启用开机启动并写入完成状态。

失败时脚本会保留已验证的 release、venv、数据库、配置和附件，记录失败阶段，并停止
失败服务。修复网络、离线包、证书、密码或数据库问题后，重新执行脚本即可自动验证并
续装；不会创建连续嵌套的回滚目录。Python 依赖已经完整安装后，续装不再强制要求离线
wheelhouse 持续挂载。

安装状态和日志位于：

```bash
sudo cat /home/operator/soc-workbench/installer/state.json
sudo less /home/operator/soc-workbench/installer/bootstrap.log
sudo cat /home/operator/soc-workbench/installer/bootstrap-last-failure.log
```

安装来源模式和离线模式会写入 `state.json`。续装期间不能从 `local` 改成 `github`，
也不能改变 `OFFLINE_MODE`，避免同一次安装混用不同来源。

## 成功验收

成功输出示例：

```text
bootstrap=ok
source_mode=local
offline_mode=1
release=<Git 提交或 local-摘要>
root=/home/operator/soc-workbench
state=/home/operator/soc-workbench/installer/state.json
```

随后执行：

```bash
sudo systemctl status soc-workbench --no-pager
curl http://127.0.0.1:5000/health
readlink -f /home/operator/soc-workbench/current
sudo cat /home/operator/soc-workbench/installer/state.json
```

健康接口必须显示：

```text
database=soc_platform_dev
database_user=soc_app
```

手工执行完整预检：

```bash
sudo -u socworkbench /bin/bash -c '
set -a
source /home/operator/soc-workbench/config/soc-workbench.env
set +a
cd /home/operator/soc-workbench/current
./venv/bin/python scripts/preflight_linux.py
'
```

预检必须包含：

```text
database=soc_platform_dev
database_user=soc_app
missing_attachments=0
preflight=ok
```

## 使用边界

`bootstrap.sh` 仅用于全新环境。检测到以下任一情况时会拒绝首次安装：

- 状态文件已经是 `complete`；
- 存在旧的 `/opt/soc-workbench`；
- 没有续装状态，但同名服务已经存在或正在运行。

新 Home 目录布局安装完成后，后续版本发布应使用适配该布局的 `update.sh`。当前任务
中的 `update.sh` 不支持旧 `/opt/soc-workbench` 布局。

## 日常更新

`update.sh` 只更新已经由新版 `bootstrap.sh` 成功安装、`state.json` 为 `complete`
且当前服务健康的 Home 布局实例。它不会重新导入 SQLite 测试种子，也不会直接修改
PostgreSQL Schema。

更新过程如下：

1. 保持当前服务运行；
2. 从本地项目或 GitHub 准备独立候选 release；
3. 为候选 release 创建独立 venv 并安装依赖；
4. 编译代码、运行全部后端测试；
5. 只补充运行目录中不存在的告警图片、附件和附件日志，不删除、不覆盖研判人员上传
   的文件；
6. 使用现有 PostgreSQL 和运行附件执行候选版本预检；
7. 预检通过后渲染 systemd 单元并原子切换 `current`；
8. 重启服务并等待最多 60 秒；
9. 健康检查失败时自动恢复旧 `current` 和旧 systemd 单元。

更新不会执行 `git pull`、`git reset --hard`，也不会创建
`before-git`、`.failed.<时间>` 等重复备份目录。旧 release 就是可直接恢复的上一
版本；失败候选会保留并在再次执行时复用。

### 本地项目更新（默认）

Windows 发布后，可以通过 SCP、内网制品库、共享目录或移动介质，把新的完整项目复制
到 Ubuntu，然后在该新项目目录执行：

```bash
cd /home/operator/agent-analysis-release
sudo bash deploy/linux/update.sh
```

如果目录中包含 `.git`，更新目标为当前提交且 Git 工作区必须干净；不包含 `.git`
时，脚本按项目内容生成 `local-<摘要>` 版本。两种方式都不连接 GitHub。

如果误在当前 release 中运行默认本地更新，并且内容没有变化，脚本会返回：

```text
update=already-current
```

### GitHub 更新

仅在目标 Ubuntu 能够访问 GitHub 和 Python 软件源时使用：

```bash
cd /home/operator/soc-workbench/current
sudo env \
  SOURCE_MODE=github \
  REPO_URL=https://github.com/timberlanm/agent-analysis.git \
  BRANCH=master \
  bash deploy/linux/update.sh
```

脚本只读取远端目标提交并克隆成新 release，不修改当前 release 的 Git 工作区。

### 完全断网更新

先按照首次断网安装章节，在相同 Ubuntu、CPU 架构和 Python 版本的联网构建机准备
Linux wheelhouse，并把它和新项目一起复制到目标机：

```bash
cd /home/operator/agent-analysis-release
sudo env \
  SOURCE_MODE=local \
  OFFLINE_MODE=1 \
  LOCAL_SOURCE_DIR="$PWD" \
  WHEELHOUSE="$PWD/deploy/offline/wheels" \
  bash deploy/linux/update.sh
```

断网更新不会访问 GitHub 或 PyPI。`update.sh` 不安装或升级 Ubuntu `.deb` 系统包；
如果新版本引入新的系统库，应先通过经过验证的离线运维流程安装，再运行更新。候选
venv 已完整安装后，续装不再要求 wheelhouse 持续挂载。

### 失败续装和放弃候选

失败信息保存在：

```text
/home/<部署用户>/soc-workbench/installer/update-state.json
/home/<部署用户>/soc-workbench/installer/update.log
/home/<部署用户>/soc-workbench/installer/update-last-failure.log
```

重新执行失败时所用的新项目目录中的 `update.sh`，脚本会恢复来源、离线模式、目标
release 和 wheelhouse 路径，并从候选版本继续验证。再次显式传入的参数必须与失败
任务一致。

如果不再继续这个失败候选，而要重新选择更新来源：

```bash
sudo env RESET_UPDATE=1 bash deploy/linux/update.sh
```

`RESET_UPDATE=1` 只放弃续装状态，不会停止当前健康服务，也不会删除运行数据。

### 数据库迁移边界

当候选代码的 Alembic head 与 PostgreSQL 当前版本不同，候选预检会失败，并保持旧
服务继续运行。`update.sh` 不会擅自升级数据库，因为 Schema 变更可能导致旧代码无法
安全回滚。此时应先制定数据库备份、迁移及回退方案，使用 `soc_migrator` 完成批准的
迁移，再重新执行更新。

### 更新成功验收

成功输出示例：

```text
update=ok
source_mode=local
offline_mode=1
old_release=<旧提交或摘要>
new_release=<新提交或摘要>
root=/home/operator/soc-workbench
state=/home/operator/soc-workbench/installer/update-state.json
```

验收命令：

```bash
sudo systemctl status soc-workbench --no-pager
curl http://127.0.0.1:5000/health
readlink -f /home/operator/soc-workbench/current
sudo cat /home/operator/soc-workbench/installer/update-state.json
```

## 当前旧测试环境专用更新

仍运行以下旧布局的现有测试环境不能使用新版 `update.sh`：

```text
/opt/soc-workbench
/opt/soc-workbench/venv
/etc/soc-workbench/soc-workbench.env
/var/lib/soc-workbench
```

该环境应单独使用：

```text
deploy/linux/update-legacy-opt.sh
```

这个脚本只用于当前可连接 GitHub 和 Python 软件源的旧 Ubuntu 测试环境，不用于新
环境或生产环境。它要求 `/opt/soc-workbench` 已经是干净的 Git 工作区，并且当前
systemd 服务使用 `/opt/soc-workbench/venv`。

更新时脚本会：

1. 确认当前服务和健康接口正常；
2. 记录当前提交和目标提交，失败后通过固定状态文件续跑；
3. 在固定目录 `/opt/soc-workbench-update-candidate` 克隆 GitHub 目标提交；
4. 使用候选版本自己的 venv 完成依赖安装、编译、测试和种子校验；
5. 准备固定的离线依赖目录，并使用当前 PostgreSQL、配置和附件执行候选预检；
6. 只有全部通过后才停止当前服务，将 `/opt/soc-workbench` 切换到目标提交并更新
   当前 venv；
7. 启动服务并等待最多 60 秒；
8. 候选阶段失败不会停止当前服务；正式切换后失败会停止服务、保留目标提交和候选
   目录，修复后重新执行同一命令即可续跑；
9. 更新成功后删除固定候选目录和临时离线依赖目录。

候选准备阶段不会停止当前服务。脚本不自动迁移 PostgreSQL Schema，也不替换当前旧
systemd 单元文件。该测试环境脚本明确不执行自动回滚，也不会创建代码、venv 或时间戳
备份目录；正式切换后的错误需要通过续跑完成修复。

### 第一次取得旧环境更新脚本

脚本尚未进入当前旧环境时，在代码发布到 GitHub 后，可以不切换当前工作区而单独导出：

```bash
cd /opt/soc-workbench
git fetch origin master
git show origin/master:deploy/linux/update-legacy-opt.sh \
  > /tmp/update-legacy-opt.sh
chmod 0750 /tmp/update-legacy-opt.sh
sudo bash /tmp/update-legacy-opt.sh
```

也可以通过 SCP 把该脚本复制到 `/tmp` 后执行。

后续更新可以继续使用当前代码中的脚本：

```bash
cd /opt/soc-workbench
sudo bash deploy/linux/update-legacy-opt.sh
```

如需明确指定 GitHub 仓库或分支：

```bash
sudo env \
  REPO_URL=https://github.com/timberlanm/agent-analysis.git \
  BRANCH=master \
  bash deploy/linux/update-legacy-opt.sh
```

如果正式切换后的失败原因是目标代码本身，需要先从 Windows 发布一个修复提交，然后
明确要求脚本放弃旧失败目标并选择 GitHub 最新提交：

```bash
cd /opt/soc-workbench
sudo env START_NEW_UPDATE=1 bash deploy/linux/update-legacy-opt.sh
```

该参数只需在选择新目标的第一次重试时使用。网络、Python 软件源、配置或其他临时错误
直接重新执行原命令即可，脚本会复用状态文件、候选目录和已准备的依赖。

更新状态和日志位于：

```text
/var/lib/soc-workbench/deploy/update-legacy-state.json
/var/lib/soc-workbench/deploy/update-legacy.log
/var/lib/soc-workbench/deploy/update-legacy-last-failure.log
```

成功输出示例：

```text
legacy_update=ok
old_commit=<旧提交>
new_commit=<新提交>
app_dir=/opt/soc-workbench
state=/var/lib/soc-workbench/deploy/update-legacy-state.json
```

失败后先检查：

```bash
sudo cat /var/lib/soc-workbench/deploy/update-legacy-last-failure.log
sudo systemctl status soc-workbench --no-pager
curl http://127.0.0.1:5000/health
git -C /opt/soc-workbench status --short
```

失败状态下不要手工删除固定候选目录或状态文件。修复错误后重新运行脚本；如果失败发生
在正式切换阶段，服务会保持停止，避免未通过健康检查的新版本继续对外提供服务。
