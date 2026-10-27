# 双仓库自动化同步与 DLP 安全脱敏系统工程文档

## 一、系统概述与业务架构

### 1.1 业务背景与资产隔离定位

本工程是一套服务于特种嵌入式研发团队的双仓库增量同步与安全脱敏服务系统，部署于中转开发机，负责协调内部真实研发库（Repo A）与对外交付验收镜像库（Repo B）之间的数据流动：
1. smart 仓库（Repo A，内部源库）：
   - 托管于内网服务器 `git@10.42.0.252:smart/smart.git`。
   - 包含主线交付应用及 20 余个内部私有子工程、内部调试工具（`gwp_debug`）及研发文档。研发人员在 Linux 无加密环境下作业。
2. smart_encrypted 仓库（Repo B，对外交付库）：
   - 托管于 `git@10.42.0.252:smart/smart_encrypted.git`。
   - 总公司即将直接介入开发与代码验收。根据研发领导“资产隔离”的核心指示，严禁交付未立项或内部未公开的子工程，且工作区源码在物理磁盘上必须携带企业 DLP 驱动特征码。

### 1.2 刚性安全红线与设计指标

1. 零泄密与防探测：总公司无法从 Repo B 的 Git 对象、提交历史中探测到 Repo A 的存在。全量清洗内网 IP、端口、私有分支名及源库哈希。
2. 资产级默认拒绝（Default-Deny）：仅放行清单批准的主线工程（`app/mickey_smart`）及公共底层组件，其余 20 个子工程源码在 Git 对象层物理剥离。
3. 终端物理合规（On-Disk DLP Compliance）：落盘源码经由 Python 受控覆写注入 `%TSD-Header-###%` 特征头并通过逻辑/物理双门禁核验。交付压缩包内 `.git/config` 静态文本严禁包含内部真实源地址。
4. 无外部 Runner 依赖：全套逻辑收敛在本地受控环境中运行，支持多仓库配置扩展。

## 二、工程目录结构说明

```text
_Workspace_/sync_repo/
├── configs/                          # 核心策略与配置文件目录
│   ├── sync_config.json              # 多仓库全局配置与实例配置表
│   ├── manifest_smart.json           # smart 仓库交付白名单清单
│   └── exclude_rules.json            # Exclude 三态排查规则与构建依赖例外
├── engine/                           # 核心同步引擎模块（v2.3.0 双向同步）
│   ├── __init__.py
│   ├── config_loader.py              # 配置加载、v2.3 状态路径解析与端点/策略 Epoch 摘要生成
│   ├── git_adapter.py                # 底层 Git Plumbing 严格退出码与三态祖先检查适配器
│   ├── path_validator.py             # 跨平台路径合法性、Windows 保留名与大小写折叠前缀树（CaseFoldedNamespaceTrie）
│   ├── content_normalizer.py         # 分类型幂等内容规范化算子（CanonHash 与 CRLF/LF 归一化）
│   ├── exclude_engine.py             # 统一自根向叶三态排查引擎（EffectiveDecision）、SharedNorm 与导出树合规验证
│   ├── process_lock.py               # OS 内核级非阻塞排他文件锁与高熵事务 ID 生成器
│   ├── dag_builder.py                # 双向状态判定矩阵（S0-S4）、拓扑排序与线性边界强校验
│   ├── tree_projector.py             # 正向（A -> B）策略记忆化全树递归投影与敏感扫描阻断
│   ├── reverse_tree_projector.py     # 反向（B -> A）受限差分叠加与完整私有补集（P_priv/A_priv）保护
│   ├── metadata_sanitizer.py         # 开发者身份双向精确白名单幂等映射与提交正文结构化清洗
│   ├── workspace_materializer.py     # 正向二次原地写加密、反向隔离暂存区 .old 解密与结构化回滚日志
│   ├── dlp_verifier.py               # 运行前四步 Canary 探针、全仓物理基线审计与 100% 增量双重门禁
│   └── transaction_manager.py        # 双向预写式事务账本（WAL v2.3）、五态远端探测恢复与 v2.2 迁移隔离
├── scripts/                          # 自动化调度、外部非受控文件执行器与客户端配置脚本
│   ├── file_ops_worker.ps1           # 结构化 JSON 清单驱动的 .NET 文件替换与父进程句柄看门狗执行器
│   ├── sync_runner.ps1               # Windows PowerShell 服务运行器（Batch/Daemon 模式）
│   ├── register_task.ps1             # Windows 计划任务注册脚本
│   ├── sync_runner.sh                # Linux Bash 运行器（支持 Cron/Daemon 调度）
│   └── setup_dev_client.sh           # 子公司研发终端配置脚本（URL 伪装与 SSH 别名）
├── tests/                            # 自动化单元与端到端故障注入测试套件（149 项自包含测试）
│   ├── test_git_adapter.py           # Git Plumbing 严格退出码、三态祖先与隔离环境测试
│   ├── test_exclude_engine.py        # 统一 EffectiveDecision、依赖例外、内容扫描与导出树校验测试
│   ├── test_path_and_content.py      # 大小写折叠前缀树、Windows 路径边界与幂等内容规范化测试
│   ├── test_tree_projectors.py       # 正反向树投影、20 个私有子工程保护与历史子树防泄漏测试
│   ├── test_metadata_sanitizer.py    # 身份精确白名单幂等与提交正文规范化测试
│   ├── test_dag_builder.py           # 双向 S0-S4 状态矩阵、OS 进程锁与线性拓扑边界测试
│   ├── test_materializer_and_dlp.py  # .old 隔离解密、Canary 探针、物理门禁与工作区回滚测试
│   └── test_transaction_and_sync_tool.py # WAL v2.3 迁移、五态远端恢复、零副作用 Dry-Run 与端到端往返测试
├── sync_tool.py                      # 统一命令行交互入口
└── README.md                         # 本工程说明文档
```

## 三、快速开始与 CLI 命令指南

引擎主入口为 `sync_tool.py`，支持双向自动/显式方向同步、零副作用只读演练、独立沙箱排练、哈希双向查询及运行状态检查：

### 3.1 运行同步命令

1. 零副作用只读演练模式（Dry-Run，推荐首次运行或变更规则时使用）：
   ```bash
   python sync_tool.py sync --dry-run [--direction {auto,a2b,b2a}]
   ```
   该模式在顶层直接分流，使用独立临时对象目录（`GIT_OBJECT_DIRECTORY`）完成正/反向树投影、敏感排查、完整私有补集不变量与 `SharedNorm` 校验，**对生产状态账本、Git 引用、索引和工作区保持 100% 零写入**。

2. 独立沙箱全流程排练模式（Isolated Rehearsal）：
   ```bash
   python sync_tool.py sync --isolated-rehearsal <sandbox_dir> [--direction {auto,a2b,b2a}]
   ```
   将双端仓库与状态复制并重绑定至独立沙箱目录执行完整工作区物化与发布排练，绝不触碰生产工作区或终止生产进程。

3. 正式双向增量发布模式（Live Production）：
   ```bash
   python sync_tool.py sync [--direction {auto,a2b,b2a}] [--no-fetch]
   ```
   自动获取 OS 内核排他文件锁，恢复未决事务，拉取远端权威跟踪引用并按 Phase 1 状态矩阵自动执行 `A -> B`（二次原地写触发 `%TSD-Header-###%` 加密）或 `B -> A`（通过 `.git/sync_staging/<tx_id>/` 下的 `.old` 通道解密并保持 Repo A 纯明文与 20 个私有子工程不变），通过双重门禁后执行带 `--force-with-lease` 的原子快进推送，同步更新本地引用、`.git/index` 与双端水位线。

4. 指定单一仓库同步：
   ```bash
   python sync_tool.py sync --repo smart [--direction {auto,a2b,b2a}]
   ```

### 3.2 提交哈希双向查询工具（防穿帮神器）

当研发同事与总公司联调时，可通过 `map` 命令秒级对齐内部与对外提交哈希：
1. 根据 Repo A 内部哈希查询对外交付哈希：
   ```bash
   python sync_tool.py map 3962aed9
   ```
   输出：
   ```text
   [+] Repo 'smart': Source Commit 3962aed93e61d3d08e8d1f60c154575f19ee94da -> Target Commit 5f0f16ab0dbe985a12f135f6bbda0b47d8c83bcc (Published)
   ```
2. 根据 Repo B 对外交付哈希反查内部源提交：
   ```bash
   python sync_tool.py map 5f0f16ab
   ```
   输出：
   ```text
   [+] Repo 'smart': Target Commit 5f0f16ab0dbe985a12f135f6bbda0b47d8c83bcc <- Source Commit(s) ['3962aed93e61d3d08e8d1f60c154575f19ee94da']
   ```

### 3.3 检查当前同步状态

```bash
python sync_tool.py status
```
实时输出各仓库两端分支 HEAD、上次发布游标、待同步提交数、当前事务阶段及映射库总量。

### 3.4 运行单元测试套件

```bash
python3 -B -m unittest discover -s tests -v
```
执行全部 149 项自动化单元与端到端验收测试（覆盖正反向树投影、完整私有补集不变量、`.old` 隔离解密与回滚、五态远端探测恢复、OS 进程锁、内容规范化与零副作用演练）。



## 四、核心配置与 Exclude 规则定制指南

### 4.1 多仓库主配置文件（configs/sync_config.json）

主配置文件划分为两级：
1. 全局设置（`global_settings`）：
   - `identity_map`：维护内部研发人员到企业官方实名与域邮箱的映射字典。未知作者将直接触发 `Fail-Closed` 阻断。
   - `default_encryption_extensions`：定义需要通过 Python 原地读写触发 Windows DLP 物理加密的源码扩展名（如 `.c`, `.h`, `.cpp`, `.py` 等）。
2. 仓库实例列表（`repositories`）：
   - 支持注册任意数量的工程对（如 `smart`、`algo_core` 等）。
   - 每个实例独立定义内部源库与外部目标库的 URL、本地物理路径、专属资产白名单路径（`manifest_path`）、专属排除规则路径（`exclude_rules_path`）及独立持久化状态库（`state_file`）。
   - 包含特定工程的历史折叠例外（`history_fold_exceptions`）与结构化提交脱敏规则（`message_sanitization_rules`）。

### 4.2 资产白名单清单（configs/manifest_smart.json）

实行严格的“默认拒绝”（Default-Deny）策略：
- `allowed_roots`：显式声明允许交付的顶层公共目录（如 `build`, `component`, `configs`, `docs`, `include`, `platform`, `release`, `thirdparty`, `tools`）。
- `app_scope`：限制 `app/` 目录下仅允许主线交付应用 `mickey_smart` 及顶层 `Makefile`。
- `legacy_anchor_b_oid`：锚定历史分界线（`5f0f16ab0dbe985a12f135f6bbda0b47d8c83bcc`），自该节点后的任何未批准新增目录默认阻断。

### 4.3 Exclude 三态规则与依赖保护清单（configs/exclude_rules.json）

1. 规则分类与动作：
   - 路径规则（`category: PATH`）：剥离非主线应用（`app/!(mickey_smart|Makefile)/**`）及内部调试目录（`gwp_debug/**`），动作为 `PRUNE`。
   - 文件名规则（`category: FILENAME`）：
     - 剥离办公文档（`*.docx`, `*.xlsx`）与临时编译产物（`*.tmp`, `*.swp`），动作为 `PRUNE`。
     - 拦截私钥凭证（`*.pem`, `*.key`, `id_rsa*`）与未经批准的外部压缩包（`*.zip`, `*.7z`），动作为 `BLOCK_REVIEW`。
2. 构建依赖例外（`approved_dependency_exceptions`）：
   - 显式白名单放行编译所必需的第三方源码归档（FFmpeg、libuv）、固件打包固件包（`tools/package/*.tar.gz`）及预编译运行库（`libasan_preinit.o`），杜绝因扩展名误杀导致的工程构建瘫痪。
3. 自研代码内容泄密扫描（`content_scanner`）：
   - 仅对自研核心源码（`app/mickey_smart/**`, `component/**`）实施深度正则排查（内网私网 IP `10.42.0.x`、私有端口 `:12123`、个人私用邮箱）。
   - 内置第三方开源头文件版权豁免清单（`approved_copyright_exceptions`），确保合法作者版权署名不被误报。
   - 每次排查在 `.sync_state/audit_<repo>_<tx_id>.json` 中输出脱敏审计报告（日志中严禁记录秘钥明文）。

## 五、服务化部署与运维守护配置

### 5.1 Windows 计划任务自动化注册（生产推荐）

在负责中转的 Windows DLP 开发机上，运行内置注册脚本即可将同步服务注册为系统级后台计划任务：

```powershell
# 以管理员权限打开 PowerShell 执行：
powershell.exe -ExecutionPolicy Bypass -File scripts\register_task.ps1 -IntervalMinutes 15
```
特性：
- 周期执行：每 15 分钟静默触发一次，无需人工干预。
- 窗口隐藏：带 `-WindowStyle Hidden` 参数，后台静默运行不弹窗。
- 进程互斥：引擎内置内核级排他文件锁 `.sync.lock`（记录持有进程 PID 与启动时间），杜绝多任务并发冲突。

### 5.2 守护进程模式（Daemon Mode）

若希望以常驻后台服务方式运行，可直接调起守护模式：
```powershell
powershell.exe -ExecutionPolicy Bypass -File scripts\sync_runner.ps1 -Mode Daemon
```
服务将在后台循环轮询，每隔 900 秒执行一次增量同步检查，日志自动追加写入 `sync.log`。

### 5.3 日志与超时监控

- 结构化日志记录于 `sync.log`，单文件达到 10MB 自动轮转（保留最近 5 份归档）。
- 固化 120 秒网络通信超时，防止偶发内网卡顿挂死守护进程。

## 六、子公司研发终端配置与协作指南

同步服务集中部署在唯一的 Windows 中转机上，子公司其他研发同事在各自开发机（Linux/macOS）上作业，必须遵循以下终端规范以实现安全伪装与口径对齐：

### 6.1 一键配置脚本

在研发工作站执行工程自带的初始化脚本：
```bash
bash scripts/setup_dev_client.sh <path_to_local_repo>
```

### 6.2 手动配置说明（底层运行机理）

1. 应用层 URL 静态伪装与内存静默重写：
   - 仓库本地配置（对外部呈现）：
     ```bash
     git remote set-url origin git@smart_repo:smart/smart_encrypted.git
     ```
     此时无论查看本地 `.git/config` 静态文本还是随压缩包交付代码，呈现的都是对外的合规镜像库 `smart_encrypted.git`。
   - 全局 Git 内存重写（`~/.gitconfig`，位于交付包外）：
     ```bash
     git config --global url."git@smart_repo:smart/smart.git".insteadOf "git@smart_repo:smart/smart_encrypted.git"
     ```
     Git 客户端在建立网络连接前，会在内存中静默将 `smart_encrypted.git` 替换为内部实际库 `smart.git`。开发者日常正常执行 `git push origin main` 或 `git pull`，数据精准流向内部库。
2. 网络层 SSH Host 别名与严格主机校验（`~/.ssh/config`）：
   ```text
   Host smart_repo
       HostName 10.42.0.252
       User git
       Port 22
       IdentityFile ~/.ssh/id_rsa_dev
   ```
   **必须预置服务器公钥至 `~/.ssh/known_hosts`，严禁使用 `StrictHostKeyChecking no`**。
3. 双 Remote 协同配置（用于直接拉取总公司视角已发布的 Hash）：
   ```bash
   git remote add origin-hq git@10.42.0.252:smart/smart_encrypted.git
   git config remote.origin-hq.pushurl "FORBIDDEN_DO_NOT_PUSH"
   ```
   开发者执行 `git fetch origin-hq` 后，查看 `git log origin-hq/main` 即可直接获得对外交付库当前的最新提交与合法 Hash，跨部门沟通直接引用该分支上的 Hash，彻底杜绝穿帮。

## 七、总公司协同与 Patch 反向回流流水线

针对总公司介入 Repo B 开发的业务场景，确立严格的“模式 A 单写主线”协作协议：

1. 主线单写与特性分支开发：
   - Repo B 的 `main` 分支设定为主线保护分支，仅允许同步服务账号拥有推送权限。
   - 总公司团队若需开发新功能或修复缺陷，必须在 Repo B 上创建 `feature/*` 或 `fix/*` 分支提交代码。
2. 受控 Patch 反向回流机制：
   - **绝对禁止在 Git 层面直接执行从 Repo B 向 Repo A 的全量分支直接合并（Merge）**。因为 Repo B 缺失了 20 个子工程，全量三方合并会将缺失应用误判为“删除”，从而抹除内部私有资产。
   - 标准回流五步流水线：
     - 步骤 1（Patch 提取）：技术负责人针对总公司特性分支提取变更 Patch（`git format-patch`）。
     - 步骤 2（白名单路径校验）：自动化核验 Patch 是否触碰非交付范围，过滤潜在的敏感配置修改。
     - 步骤 3（三方合入）：在内部 Repo A 检出专用集成验证分支，通过 `git am -3` 将 Patch 合入。
     - 步骤 4（本地编译回归）：在 Linux 开发机执行交叉编译与硬件回归测试，验证无误后合入 Repo A 的 `main` 分支。
     - 步骤 5（正向投影）：由同步服务正常向前推进，将该成果正向投影重构回 Repo B 的 `main` 分支。
   - 内部维护 `hq_commit_oid → imported_a_commit_oid` 映射记录，对已导入的提交进行幂等去重，防止二次回流产生循环冲突。
