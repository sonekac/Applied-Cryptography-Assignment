# Applied-Cryptography-Assignment
## Introduction
The work consists on implementing a variant of DES (E-DES), which will be similar to DES but with a
longer, 256-bit key and faster functions on the Feistel networks. The input and output
blocks must have the same size, 64 bits.git

## How to run
```console
gcc PKCS7_ECB.c PKCS7_ECB.h main.c E-DES.h E-DES.c utils.h utils.c -o test -lssl -lcrypto && ./test plaintext key
```

## TO DO

* Need to add error handling