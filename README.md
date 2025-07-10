-----

# 🔐 2FA 安全管理系统 

一个基于 Cloudflare Workers 的现代化双因素认证(2FA)管理系统，提供安全的 TOTP 代码生成、账户管理和云端备份功能。

-----

## ✨ 特性

### 🛡️ 安全特性

  * **OAuth 2.0 授权登录** - 支持第三方 OAuth 服务安全认证
  * **自动账号管理** - OAuth登录时自动创建或绑定用户账号
  * **多用户数据隔离** - 每个用户的数据完全独立，互不可见
  * **端到端加密** - 所有敏感数据使用 AES-GCM 加密存储
  * **JWT 会话管理** - 2小时自动过期的安全会话
  * **速率限制保护** - 防止暴力攻击和 API 滥用
  * **安全审计日志** - 记录所有重要操作和安全事件

### 📱 2FA 管理

  * **多种添加方式** - 手动输入、二维码扫描、图片上传
  * **TOTP 代码生成** - 支持 6/8 位验证码，30/60 秒周期
  * **智能账户分类** - 自定义分类标签和快速搜索
  * **实时代码显示** - 带进度条的验证码倒计时
  * **一键复制功能** - 自动复制验证码到剪贴板

### ☁️ 云端备份

  * **WebDAV 自动备份** - 支持 Nextcloud、ownCloud、TeraCloud 等
  * **多账号管理** - 可配置多个 WebDAV 存储账号
  * **加密备份文件** - 密码保护的备份文件
  * **智能目录结构** - 按年/月/日自动组织备份文件
  * **备份历史管理** - 查看、下载、恢复历史备份

### 📥📤 数据迁移

  * **多格式导入** - 支持 JSON、2FAS、纯文本格式
  * **加密导出** - 密码保护的安全导出
  * **批量操作** - 支持批量导入和去重处理
  * **数据验证** - 严格的数据格式验证和清理

-----

## 🚀 快速开始

### 环境要求

  * Cloudflare Workers 账号
  * Wrangler CLI 工具
  * OAuth 2.0 认证服务器（如 GitHub、GitLab、自建等）

### 部署步骤

1.  **克隆仓库**

    ```bash
    git clone https://github.com/ilikeeu/2fauth.git
    cd 2fauth
    ```

2.  **安装依赖**

    ```bash
    npm install -g wrangler
    ```

3.  **创建 KV 命名空间**

    ```bash
    wrangler kv:namespace create "USER_DATA"
    wrangler kv:namespace create "USER_DATA" --preview
    ```

4.  **配置 `wrangler.toml`**

    ```toml
    name = "2fa-secure-manager"
    main = "src/index.js"
    compatibility_date = "2024-01-15"

    [[kv_namespaces]]
    binding = "USER_DATA"
    id = "your-kv-namespace-id"
    preview_id = "your-preview-kv-namespace-id"

    [vars]
    OAUTH_BASE_URL = "https://your-oauth-server.com"
    OAUTH_REDIRECT_URI = "https://your-domain.workers.dev/api/oauth/callback"
    # OAUTH_ID = "authorized_user_id"  # 可选：向后兼容，新版本支持自动用户注册

    [env.production.vars]
    ALLOWED_ORIGINS = "https://your-domain.workers.dev"
    ```

5.  **设置环境变量**

    ```bash
    # OAuth 配置
    wrangler secret put OAUTH_CLIENT_ID
    wrangler secret put OAUTH_CLIENT_SECRET

    # 安全密钥
    wrangler secret put JWT_SECRET
    wrangler secret put ENCRYPTION_KEY
    ```

6.  **部署到 Cloudflare Workers**

    ```bash
    wrangler deploy
    ```

-----

## ⚙️ 配置说明

### 必需的环境变量

| 变量名             | 描述           | 示例                           |
| :----------------- | :------------- | :----------------------------- |
| `OAUTH_CLIENT_ID`  | OAuth 客户端 ID | `your_oauth_client_id`         |
| `OAUTH_CLIENT_SECRET` | OAuth 客户端密钥 | `your_oauth_client_secret`     |
| `OAUTH_BASE_URL`   | OAuth 服务器地址 | `https://oauth.example.com`    |
| `OAUTH_REDIRECT_URI` | OAuth 回调地址 | `https://your-app.workers.dev/api/oauth/callback` |
| `OAUTH_ID`         | 授权用户 ID    | `12345`                        |
| `JWT_SECRET`       | JWT 签名密钥   | `your_strong_jwt_secret`       |
| `ENCRYPTION_KEY`   | 数据加密密钥   | `your_encryption_key`          |

### 可选的环境变量

| 变量名           | 描述         | 默认值 |
| :--------------- | :----------- | :----- |
| `ALLOWED_ORIGINS` | 允许的跨域来源 | `*`    |

### OAuth 服务器配置

系统支持任何标准的 OAuth 2.0 服务器。以下是一些常见的配置示例：

#### GitHub OAuth App

```
OAUTH_BASE_URL=https://github.com
OAUTH_CLIENT_ID=your_github_client_id
OAUTH_CLIENT_SECRET=your_github_client_secret
OAUTH_REDIRECT_URI=https://your-app.workers.dev/api/oauth/callback
# OAUTH_ID不再是必需的，系统支持自动用户注册
```

#### 自建 OAuth 服务器

```
OAUTH_BASE_URL=https://your-oauth-server.com
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_REDIRECT_URI=https://your-app.workers.dev/api/oauth/callback
# OAUTH_ID不再是必需的，系统支持自动用户注册
```

-----

## 📖 使用指南

### 基本操作

1.  **登录系统**

      * **OAuth登录**：点击"第三方授权登录"按钮
        - 在 OAuth 服务器完成授权
        - 系统自动创建或绑定您的账号
        - 自动跳转回系统主界面
      * **密码登录**：使用用户名/邮箱和密码登录
        - 支持用户注册功能
        - 与OAuth账号完全独立

2.  **添加 2FA 账户**

      * **手动添加**：输入服务名称、账户信息和 Base32 密钥
      * **扫描二维码**：使用摄像头扫描或上传二维码图片
      * **批量导入**：从其他 2FA 应用导入数据

3.  **生成验证码**

      * 点击账户卡片查看验证码
      * 验证码自动复制到剪贴板
      * 实时显示剩余有效时间

### WebDAV 备份配置

1.  **添加 WebDAV 账号**

      * 输入 WebDAV 服务器地址
      * 配置用户名和密码
      * 设置备份目录路径

2.  **自动备份**

      * 点击"立即备份"创建加密备份
      * 备份文件按日期自动组织
      * 支持多个 WebDAV 账号管理

3.  **恢复备份**

      * 查看备份文件列表
      * 选择要恢复的备份文件
      * 输入备份密码完成恢复

### 数据导入导出

#### 支持的导入格式

  * **加密备份文件** - 本系统导出的加密文件
  * **JSON 格式** - 标准 JSON 或 2FAuth 格式
  * **2FAS 格式** - 2FAS 应用的备份文件
  * **纯文本格式** - 包含 TOTP URI 的文本文件

#### 导出选项

  * **加密导出** - 密码保护的安全备份文件
  * **WebDAV 备份** - 直接上传到云存储

-----

## 🔒 安全说明

### 数据保护

  * **本地加密**：所有敏感数据在存储前使用 AES-GCM 加密
  * **传输安全**：全程 HTTPS 加密传输
  * **密钥管理**：使用强随机密钥和盐值
  * **访问控制**：基于 OAuth 2.0 的身份验证
  * **自动账号管理**：OAuth登录时自动创建或绑定账号

### 隐私保护

  * **最小权限**：只请求必要的 OAuth 权限
  * **数据隔离**：每个用户的数据完全隔离
  * **会话管理**：2小时自动过期的安全会话
  * **审计日志**：记录但不存储敏感操作详情
  * **用户隔离**：每个OAuth账号独立管理，数据互不可见

### 安全建议

  * **强密码策略**：导出密码至少 12 个字符
  * **定期备份**：建议每周进行一次完整备份
  * **环境隔离**：生产环境使用独立的 OAuth 应用
  * **密钥轮换**：定期更新 JWT 和加密密钥

-----

## 🛠️ 开发指南

### 项目结构

```
2fa-secure-manager/
├── src/
│   └── index.js          # 主应用文件
├── wrangler.toml         # Cloudflare Workers 配置
├── package.json          # 项目依赖
└── README.md             # 项目文档
```

### 本地开发

  * **启动开发服务器**
    ```bash
    wrangler dev
    ```
  * **查看日志**
    ```bash
    wrangler tail
    ```
  * **测试部署**
    ```bash
    wrangler deploy --dry-run
    ```

### API 接口

#### 认证相关

  * `GET /api/oauth/authorize` - 获取 OAuth 授权 URL
  * `GET|POST /api/oauth/callback` - OAuth 回调处理

#### 账户管理

  * `GET /api/accounts` - 获取账户列表
  * `POST /api/accounts` - 添加新账户
  * `PUT /api/accounts/:id` - 更新账户信息
  * `DELETE /api/accounts/:id` - 删除账户
  * `DELETE /api/accounts/clear-all` - 清空所有账户

#### TOTP 功能

  * `POST /api/generate-totp` - 生成 TOTP 验证码
  * `POST /api/parse-uri` - 解析 TOTP URI
  * `POST /api/add-from-uri` - 从 URI 添加账户

#### 数据备份

  * `GET /api/export-secure` - 加密导出数据
  * `POST /api/import` - 导入数据
  * `POST /api/import-secure` - 导入加密数据

#### WebDAV 功能

  * `POST /api/test-webdav` - 测试 WebDAV 连接
  * `POST /api/list-webdav-backups` - 列出备份文件
  * `POST /api/export-webdav` - 导出到 WebDAV
  * `POST /api/restore-webdav` - 从 WebDAV 恢复
  * `POST /api/download-webdav` - 下载备份文件

-----

## 🤝 贡献指南

我们欢迎各种形式的贡献！

### 报告问题

如果您发现了 bug 或有功能建议，请：

  * 查看现有的 [Issues](https://www.google.com/search?q=https://github.com/your-username/2fa-secure-manager/issues)
  * 创建新的 Issue 并详细描述问题
  * 提供复现步骤和环境信息

### 提交代码

1.  Fork 本仓库
2.  创建功能分支：`git checkout -b feature/amazing-feature`
3.  提交更改：`git commit -m 'Add amazing feature'`
4.  推送分支：`git push origin feature/amazing-feature`
5.  创建 Pull Request

### 开发规范

  * 遵循现有的代码风格
  * 添加必要的注释和文档
  * 确保所有功能都有适当的错误处理
  * 遵循安全最佳实践

-----

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](https://www.google.com/search?q=LICENSE) 文件了解详情。

-----

## 🙏 致谢

  * [Cloudflare Workers](https://workers.cloudflare.com/) - 无服务器计算平台
  * [jsQR](https://github.com/cozmo/jsQR) - JavaScript 二维码解析库
  * [Web Crypto API](https://developer.mozilla.org/zh-CN/docs/Web/API/Web_Crypto_API) - 浏览器加密 API

-----

## 📞 支持

如果您需要帮助或有任何问题：

  * 📧 **邮箱**：your-email@example.com
  * 💬 **讨论**：[GitHub Discussions](https://www.google.com/search?q=https://github.com/your-username/2fa-secure-manager/discussions)
  * 🐛 **Bug 报告**：[GitHub Issues](https://www.google.com/search?q=https://github.com/your-username/2fa-secure-manager/issues)

⭐ 如果这个项目对您有帮助，请给我们一个 Star！
