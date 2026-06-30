# CovScript GmSSL CNI API Reference

CovScript 国密算法扩展，基于 [GmSSL](https://github.com/guanzhi/GmSSL) 3.x。

## 工具函数

| 函数 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `bytes_encode` | `(str) → bytes` | `bytes_array` | 字符串转字节数组 |
| `bytes_decode` | `(bytes) → str` | `string` | 字节数组转字符串 |
| `hex_encode` | `(bytes) → str` | `string` | 字节数组转 hex 字符串（小写） |
| `hex_decode` | `(bytes) → bytes` | `bytes_array` | hex 字节数组转二进制 |
| `base64_encode` | `(bytes) → str` | `string` | 字节数组转 base64 字符串 |
| `base64_decode` | `(bytes) → str` | `string` | base64 字节数组转原始数据 |
| `rand_bytes` | `(count: int) → bytes` | `bytes_array` | 生成 `count` 个密码学安全随机字节 |
| `rand_chars` | `(count: int, seed: int) → str` | `string` | 生成 `count` 个随机字符（确定性，基于种子） |
| `secure_clear` | `(bytes) → void` | - | 安全清除字节数组内容（防内存残留） |

## SM2 椭圆曲线

### 密钥管理

| 函数 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `sm2_key_generate` | `(passwd: str) → [pubkey, privkey]` | `array` | 生成 SM2 密钥对。私钥使用密码加密存储（DER 格式） |
| `sm2_pem_read` | `(path: str, name: str) → bytes` | `bytes_array` | 从 PEM 文件读取密钥 |
| `sm2_pem_write` | `(path: str, name: str, key: bytes) → void` | - | 将密钥写入 PEM 文件 |

| 常量 | 值 | 说明 |
|------|-----|------|
| `pem_name_pbk` | `"PUBLIC KEY"` | PEM 公钥标签 |
| `pem_name_pvk` | `"EC PRIVATE KEY"` | PEM 私钥标签 |

### 签名与验签

| 函数 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `sm2_sign` | `(privkey: bytes, passwd: str, id: str, data: bytes) → bytes` | `bytes_array` | SM2 签名 |
| `sm2_verify` | `(pubkey: bytes, sig: bytes, id: str, data: bytes) → bool` | `boolean` | SM2 验签。返回 `true` 表示验证通过 |

### 加密与解密

| 函数 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `sm2_encrypt` | `(pubkey: bytes, data: bytes) → bytes` | `bytes_array` | SM2 公钥加密。明文最大 255 字节 |
| `sm2_decrypt` | `(privkey: bytes, passwd: str, data: bytes) → bytes` | `bytes_array` | SM2 私钥解密 |

### ECDH 密钥协商

| 函数 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `sm2_ecdh` | `(privkey: bytes, passwd: str, peer_pubkey: bytes) → bytes` | `bytes_array` | SM2 ECDH 密钥协商。输出 32 字节共享密钥 |

### SM2 常量

| 常量 | 类型 | 值 | 说明 |
|------|------|-----|------|
| `sm2_max_signature_size` | `int` | 72 | SM2 签名最大长度（字节） |
| `sm2_max_plaintext_size` | `int` | 255 | SM2 加密明文最大长度（字节） |
| `sm2_max_ciphertext_size` | `int` | 366 | SM2 密文最大长度（字节） |
| `ecdh_shared_key_size` | `int` | 32 | ECDH 共享密钥长度（字节） |

## SM3 杂凑算法

| 函数 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `sm3` | `(data: bytes) → bytes` | `bytes_array` | SM3 哈希，输出 32 字节摘要 |
| `sm3_hmac` | `(key: bytes, data: bytes) → bytes` | `bytes_array` | SM3 HMAC 消息认证码，输出 32 字节 |
| `sm3_pbkdf2` | `(pass: str, salt: bytes, iter_count: int, outlen: int) → bytes` | `bytes_array` | PBKDF2 密钥派生。迭代次数必须 ≥ `sm3_pbkdf2_min_iter` |

### SM3 常量

| 常量 | 类型 | 值 | 说明 |
|------|------|-----|------|
| `sm3_digest_size` | `int` | 32 | SM3 摘要长度（字节） |
| `sm3_pbkdf2_min_iter` | `int` | 10000 | PBKDF2 最小迭代次数 |
| `sm3_pbkdf2_max_iter` | `int` | 16777215 | PBKDF2 最大迭代次数 |
| `sm3_pbkdf2_max_salt_size` | `int` | 64 | PBKDF2 salt 最大长度（字节） |

## SM4 分组密码

### 加密与解密

| 函数 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `sm4` | `(mode: sm4_mode, key: bytes, iv: bytes, data: bytes) → bytes` | `bytes_array` | SM4 加密/解密。密钥和 IV 均为 16 字节 |

### SM4 模式枚举

| 常量 | 说明 |
|------|------|
| `sm4_mode.cbc_encrypt` | CBC 模式加密 |
| `sm4_mode.cbc_decrypt` | CBC 模式解密 |
| `sm4_mode.ctr_encrypt` | CTR 模式加密 |
| `sm4_mode.ctr_decrypt` | CTR 模式解密 |

### SM4 CBC-MAC

| 函数 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `sm4_cbc_mac` | `(key: bytes, data: bytes) → bytes` | `bytes_array` | SM4 CBC-MAC 消息认证码，输出 16 字节 |

### SM4 常量

| 常量 | 类型 | 值 | 说明 |
|------|------|-----|------|
| `sm4_key_size` | `int` | 16 | SM4 密钥长度（字节） |
| `sm4_cbc_mac_size` | `int` | 16 | CBC-MAC 输出长度（字节） |

## ZUC 流密码

| 函数 | 签名 | 返回值 | 说明 |
|------|------|--------|------|
| `zuc_encrypt` | `(key: bytes, iv: bytes, data: bytes) → bytes` | `bytes_array` | ZUC-128 流加密。加解密对称（同一函数） |

### ZUC 常量

| 常量 | 类型 | 值 | 说明 |
|------|------|-----|------|
| `zuc_key_size` | `int` | 16 | ZUC 密钥长度（字节） |
| `zuc_iv_size` | `int` | 16 | ZUC IV 长度（字节） |

## 类型说明

| CovScript 类型 | C++ 类型 | 说明 |
|---------------|----------|------|
| `bytes_array` | `std::vector<uint8_t>` | 字节数组，可通过 `bytes_encode`/`bytes_decode` 与字符串互转 |
| `string` | `std::string` | 字符串 |
| `int` | `int` / `size_t` | 整数 |
| `boolean` | `bool` | 布尔值 |

**隐式类型转换**：`string` 可自动转换为 `bytes_array`（等效于 `bytes_encode`），但建议显式使用 `bytes_encode` 以确保代码清晰。
