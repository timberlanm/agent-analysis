# Ubuntu 22.04 测试环境部署

Windows 开发机负责构建并提交 `frontend/dist`。Ubuntu 不安装 Node.js，只拉取
GitHub、安装 Python 依赖、同步测试附件、校验 PostgreSQL 并重启服务。

## 仓库与运行目录

```text
/opt/soc-workbench/                         GitHub代码
/opt/soc-workbench/venv/                    Python虚拟环境
/var/lib/soc-workbench/data/                Flask密钥和初始化报告
/var/lib/soc-workbench/uploads/incident/    实际附件目录
/etc/soc-workbench/soc-workbench.env        运行配置
/etc/soc-workbench/soc-workbench.migration.env  初始化/迁移配置
```

仓库提交以下测试种子：

```text
backend/data/analysis_store.db
backend/uploads/incident/
frontend/dist/
```

`analysis_store.db` 保存历史告警、用户权限、附件元数据和研判记录。图片、附件和
日志的物理文件保存在 `backend/uploads/incident`。

## 配置文件

运行配置：

```bash
sudo install -o root -g socworkbench -m 0640 \
  deploy/linux/soc-workbench.env.example \
  /etc/soc-workbench/soc-workbench.env
sudo nano /etc/soc-workbench/soc-workbench.env
```

初始化/迁移配置：

```bash
sudo install -o root -g root -m 0600 \
  deploy/linux/soc-workbench.migration.env.example \
  /etc/soc-workbench/soc-workbench.migration.env
sudo nano /etc/soc-workbench/soc-workbench.migration.env
```

数据库与应用位于同一台 Ubuntu，两个连接串都固定使用
`127.0.0.1:5432`，不填写局域网IP。

## 首次初始化

先将仓库克隆到临时目录，完成两个配置文件，然后以 Linux 登录用户运行：

```bash
git clone https://github.com/timberlanm/agent-analysis.git \
  /home/hacker/agent-analysis-bootstrap
cd /home/hacker/agent-analysis-bootstrap
bash deploy/linux/bootstrap.sh
```

脚本会：

1. 安装 Git、Python、venv、rsync等运行依赖，不安装 Node.js；
2. 备份已有的非Git `/opt/soc-workbench`；
3. 从 GitHub克隆 `master`；
4. 创建虚拟环境并安装 Python依赖；
5. 将仓库测试附件同步到 `/var/lib/soc-workbench`；
6. 对空 PostgreSQL执行 Alembic并导入 SQLite历史队列；
7. 对非空 PostgreSQL跳过种子导入；
8. 校验数据库版本、历史告警和全部附件；
9. 安装并启动 systemd服务；
10. 验证 `/health`。

## 日常一键更新

Ubuntu代码目录禁止直接修改。Windows发布完成后执行：

```bash
cd /opt/soc-workbench
bash deploy/linux/update.sh
```

更新脚本不会执行 npm，也不会重复导入 SQLite种子。它会：

1. `git pull --ff-only`；
2. 从 requirements增量安装 Python包；
3. 执行编译和测试；
4. 增量同步仓库测试附件，不删除运行环境新增附件；
5. 比较代码 Alembic head 与 PostgreSQL版本；
6. 执行完整预检；
7. 重启服务并检查健康接口；
8. 失败时恢复更新前 Git提交。

出现新的 Alembic版本时，预检会停止发布。完成数据库备份并使用
`soc_migrator`迁移后，再重新运行更新脚本。

## 手工预检

```bash
sudo -u socworkbench /bin/bash -c '
set -a
source /etc/soc-workbench/soc-workbench.env
set +a
cd /opt/soc-workbench
./venv/bin/python scripts/preflight_linux.py
'
```

必须输出：

```text
database=soc_platform_dev
database_user=soc_app
missing_attachments=0
preflight=ok
```
