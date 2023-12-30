# README.md

## 系统介绍

本项目是一个基于 Flask 框架的 QQ 登录认证系统，旨在为用户提供一种安全、便捷的方式来验证其身份并加入特定的 QQ 群。本系统的设计灵感来源于上海交通大学的类似项目（参考 [SJTU-Plus](https://github.com/SJTU-Plus/sjtu-plus/blob/master/docs/whitepaper.md)）。系统主要包括令牌签发和令牌验证两部分。

### 令牌签发

令牌签发部分是一个 Web 服务。用户通过网站登录，并输入自己的 QQ 号码。系统针对该 QQ 号码签发一个带有时间戳的令牌，用于后续的身份验证。

### 令牌验证

令牌验证主要由 QQ 群的 Bot 管理员执行。用户在申请加入 QQ 群时提交令牌，QQ 群 Bot 拦截加群请求并进行令牌验证。若令牌有效，Bot 根据配置的有效期决定是否允许用户加入群聊。

### 实践应用

在实际应用中，SJTU-Plus 提供了一个验证接口服务，QQ 群管理员可以搭建验证 Bot 并通过我们的网络接口进行验证。

## 基于 AES-CMAC 的令牌方案

本系统采用的是基于 AES-CMAC 的令牌方案。签发服务器和验证服务器需配置相同的 AES 密钥 `secret`。当用户提交 QQ 号给签发服务器时，服务器生成 Token。

```
Token = Base58Encode(timestamp || AES-CMAC(secret, timestamp || qq_number))
```

用户在申请加入群聊时提交 Token，验证服务器（QQ 群 Bot 管理员）进行 Base58 解码，提取时间戳，并验证 MAC。

## 系统结构及其部署

请参考项目中的 `config/sustech.py` 文件进行系统配置，并根据 Flask 应用的部署方式运行本项目。部署时需确保服务器环境满足所有依赖要求，并正确配置 OAuth 和数据库设置。

## 许可证

本项目遵循 MIT 许可证发布。请查阅 `LICENSE` 文件了解更多详情。