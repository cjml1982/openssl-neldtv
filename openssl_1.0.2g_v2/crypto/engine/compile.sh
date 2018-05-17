#!/bin/bash
#将该eng_cryptodev.c文件放置于openssl编译目录中的crypto/engine文件下，然后按照用户使用手册中的引擎编译的步骤编译即可。
gcc -Wall  -I.. -I../.. -I../modes -I../asn1 -I../evp -I../../include  -fPIC -DOPENSSL_PIC -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DENGINE_DYNAMIC_SUPPORT -Wa,--noexecstack -m64 -DL_ENDIAN -O3 -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DHAVE_CRYPTODEV -c -o eng_cryptodev.o eng_cryptodev.c

gcc -shared eng_cryptodev.o -o libeng_cryptodev.so -lcrypto -L../../