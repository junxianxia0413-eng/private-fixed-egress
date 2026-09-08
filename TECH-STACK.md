# 技术栈

| 层 | 选择 |
| --- | --- |
| Controller / Gateway OS | Debian 12 |
| Python | 3.11+；CI 覆盖 3.11 与 3.14 |
| API | FastAPI + Uvicorn，单 worker |
| Dashboard | Jinja2 + HTML/CSS，渐进增强 |
| 数据库 | SQLite，事务迁移、WAL、在线备份 |
| 管理员密码 | Argon2id |
| 会话 | 随机 opaque token，服务端摘要存储 |
| HTTPS | Caddy |
| 服务 | systemd，非 root 运行 |
| Gateway 核心（后续） | sing-box |
| Gateway 防火墙（后续） | nftables |
| 自动部署（后续） | Python SSH + Shell |
| 配置 | YAML + .env，secrets/ 秘密文件 |

`requirements.in` 声明直接依赖范围；`requirements.txt` 锁定经过测试的完整运行依赖。
`requirements-dev.txt` 锁定开发和测试依赖。更新后须重新测试，不依赖部署时浮动解析。

