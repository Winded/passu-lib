This is the shared package for [passu](https://github.com/Winded/passu), used by all clients.

## Security

I believe this program to be secure enough, but keep in mind I'm not a security expert and this is free software, so use at your own risk.

The password file is a JSON string encrypted with AES-256-CBC. The encryption key is the master password hashed with [scrypt](https://golang.org/x/crypto/scrypt). The hash and salt are both 256 bits, and the initialization vector for AES-CBC is 128 bits.