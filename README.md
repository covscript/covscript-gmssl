# GmSSL Support for CovScript

This project is based on [guanzhi/GmSSL](https://github.com/guanzhi/GmSSL)

Requirements: CovScript SDK > v3.4.3.15

## Supported Algorithms

 + SM2
   + SM2 PEM Read/Write
   + SM2 Key Pair Generation
   + SM2 Sign/Verify
   + SM2 Encrypt/Decrypt
 + SM3
   + Standard SM3 Digest
   + SM3 Digest with HMAC
   + SM3 Digest with PBKDF2
 + SM4
   + CBC Mode Encrypt/Decrypt
   + CTR Mode Encrypt/Decrypt
 + Utilities
   + Secure Clear (Secure wipe content of bytes array)
   + Random Chars (Reproducible visible chars generator based on mt19937 algorithm)
   + Random Bytes (Use robust algorithm from guanzhi/GmSSL)

