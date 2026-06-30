# GmSSL Support for CovScript

基于 [GmSSL](https://github.com/guanzhi/GmSSL) 3.x 的 CovScript 国密算法扩展。

## 功能

+ SM2 椭圆曲线
  + PEM 密钥读写
  + 密钥对生成
  + 签名 / 验签
  + 加密 / 解密
  + ECDH 密钥协商
+ SM3 杂凑算法
  + 哈希摘要
  + HMAC 消息认证码
  + PBKDF2 密钥派生
+ SM4 分组密码
  + CBC 模式加密 / 解密
  + CTR 模式加密 / 解密
  + CBC-MAC 消息认证码
+ ZUC 流密码
  + ZUC-128 加密 / 解密
+ 工具函数
  + bytes / hex / base64 编解码
  + 密码学安全随机数
  + 安全内存清除

## 构建

依赖：CovScript SDK，需设置 `CS_DEV_PATH` 环境变量。

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## 测试

```bash
CS="/path/to/cs"
for t in tests/test_*.csc; do
    "$CS" -i build/imports "$t"
done
```

测试套件：

| 文件 | 覆盖范围 |
|------|---------|
| `test_util.csc` | 工具函数（编解码、随机数） |
| `test_sm3.csc` | SM3 哈希、HMAC、PBKDF2 |
| `test_sm2.csc` | SM2 密钥、签名、加解密、ECDH |
| `test_sm4.csc` | SM4 CBC/CTR、CBC-MAC |
| `test_zuc.csc` | ZUC 加解密 |
| `test_error.csc` | 错误路径和异常处理 |

## 文档

+ [CNI_API.md](CNI_API.md) — CovScript 脚本侧 API 参考
+ [SIMPLE_TLS.md](SIMPLE_TLS.md) — 基于国密算法的简易 TLS 库
+ [ARGPARSE.md](ARGPARSE.md) — 命令行参数解析库

## 项目结构

```
covscript-gmssl/
  gmssl.cpp              -- CNI 绑定层
  gmssl.hpp              -- C++ 包装器
  CMakeLists.txt         -- 构建配置
  GmSSL/                 -- GmSSL 子模块
  tests/                 -- 单元测试
  .github/workflows/     -- CI 配置
  ecdh.csc               -- ECDH 示例
  sm2_encrypt.csc        -- SM2 加密示例
  sm2_decrypt.csc        -- SM2 解密示例
  sm4_encrypt.csc        -- SM4 加密示例
  sm4_decrypt.csc        -- SM4 解密示例
  sm4_cbc_mac.csc        -- SM4 CBC-MAC 示例
  zuc_encrypt.csc        -- ZUC 加密示例
  passcode.ecs           -- 密码管理工具
  CNI_API.md             -- API 文档
```
