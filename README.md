# RSA_generator
openssl의 BIGNUM을 활용하여 공개키 , 개인키를 생성하고 서명 및 검증
k 옵션으로 공개키 및 개인키 생성 가능
e 옵션으로 평문에 대한 공개키 암호화 
d 옵션으로 공개키 암호화를 복호화

# Usage
* build rsa_임정환.c
* ./<exe> [-k | -e e n plaintext | -d d n ciphertext ]

# Dependency
* openssl version3.0
