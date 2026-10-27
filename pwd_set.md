参考PWD设置：

```
    _Workspace_/
    ├── smart                     (项目 1 的内部源仓库 Repo A)
    ├── smart_encrypted           (项目 1 的对外交付仓库 Repo B)
    ├── algo                      (项目 2 的内部源仓库 Repo A，示例)
    ├── algo_encrypted            (项目 2 的对外交付仓库 Repo B，示例)
    └── sync_repo/                (统一调度与安全引擎服务)
        ├── configs/              (各项目配置与清单)
        ├── engine/               (同步核心流水线)
        ├── scripts/              (计划任务与客户端脚本)
        ├── .sync_state/          (各项目的同步状态、游标与审计日志)
        └── sync_tool.py          (主入口工具)
```