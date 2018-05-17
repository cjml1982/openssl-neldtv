#!/bin/bash
# author: yfma
#test hash algorithms

dynamic_engine="./libeng_cryptodev.so"

if [ ! -n "$1" ]; then
  echo -e "\e[1;31mPlease specify the test file name.\e[0m"
  exit 0
else
  if [ ! -f "$1" ]; then
    echo -e "\e[1;31m$1 is not exist.\e[0m"
    exit 0
  fi
  echo -e "\e[1;32m\r\n----------------------------------------hash test start.----------------------------------------\e[0m"
fi

echo -e "\e[1;34m\r\n1.start md5 test\e[0m"
data_s=`./openssl md5 $1 | awk '{split($2,a,"=");print a[1]}'`
echo "software result=$data_s"
data_h=`./openssl md5 -engine $dynamic_engine $1 | awk '{split($2,a,"=");print a[1]}'`
echo "$dynamic_engine result=$data_h"
if [ "${data_s}" = "${data_h}" ]; then
  echo -e "\e[1;36mmd5 calc success.\e[0m"
else
  echo -e "\e[1;31mmd5 calc failed.\e[0m"
  exit 0
fi


echo -e "\e[1;34m\r\n2.start sha1 test\e[0m"
data_s=`./openssl sha1 $1 | awk '{split($2,a, "=");print a[1]}'`
echo "software result=$data_s"
data_h=`./openssl sha1 -engine $dynamic_engine $1 | awk '{split($2,a,"=");print a[1]}'`
echo "$dynamic_engine result=$data_h"
if [ "${data_s}" = "${data_h}" ]; then
  echo -e "\e[1;36msha1 calc success.\e[0m"
else
  echo -e "\e[1;31msha1 calc failed.\e[0m"
  exit 0
fi


echo -e "\e[1;34m\r\n3.start sha1 test\e[0m"
data_s=`./openssl sha256 $1 | awk '{split($2,a, "=");print a[1]}'`
echo "software result=$data_s"
data_h=`./openssl sha256 -engine $dynamic_engine $1 | awk '{split($2,a,"=");print a[1]}'`
echo "$dynamic_engine result=$data_h"
if [ "${data_s}" = "${data_h}" ]; then
  echo -e "\e[1;36msha256 calc success.\e[0m"
else
  echo -e "\e[1;31msha256 calc failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n4.start hmac-sha1 test\e[0m"
data_s=`./openssl dgst -hmac 123456 -sha1 $1 | awk '{print $2}'`
echo "software result=$data_s"
data_h=`./openssl dgst -hmac 123456 -sha1 -engine $dynamic_engine $1 | awk '{print $2}'`
echo "$dynamic_engine result=$data_h"
if [ "${data_s}" = "${data_h}" ]; then
  echo -e "\e[1;36mhmac-sha1 calc success.\e[0m"
else
  echo -e "\e[1;31mhmac-sha1 calc failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n5.start hmac-sha256 test\e[0m"
data_s=`./openssl dgst -hmac 123456 -sha256 $1 | awk '{print $2}'`
echo "software result=$data_s"
data_h=`./openssl dgst -hmac 123456 -sha256 -engine $dynamic_engine $1 | awk '{print $2}'`
echo "$dynamic_engine result=$data_h"
if [ "${data_s}" = "${data_h}" ]; then
  echo -e "\e[1;36mhmac-sha256 calc success.\e[0m"
else
  echo -e "\e[1;31mhmac-sha256 calc failed.\e[0m"
  exit 0
fi

echo -e "\e[1;32m\r\n-----------------------------------------hash test end.-------------------------------------------\e[0m"

echo -e "\e[1;32m\r\n----------------------------------------aes test start.-------------------------------------------\e[0m"

echo -e "\e[1;34m\r\n1.start aes-128-cbc test\e[0m"


#hardware encrypt
./openssl aes-128-cbc -e -base64 -in $1 -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_128_cbc_enc
#soft decrypt
./openssl aes-128-cbc -d -base64 -in h_aes_128_cbc_enc -iv 123456  -k 123456 -out s_aes_128_cbc_dec
result=`diff $1 s_aes_128_cbc_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-128-cbc encrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-128-cbc encrypt test failed.\e[0m"
  exit 0
fi

#soft encrypt
./openssl aes-128-cbc -e -base64 -in $1 -iv 123456 -k 123456 -out s_aes_128_cbc_enc
#hardware decrypt
./openssl aes-128-cbc -d -base64 -in s_aes_128_cbc_enc -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_128_cbc_dec
result=`diff $1 h_aes_128_cbc_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-128-cbc decrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-128-cbc decrypt test failed.\e[0m"
  exit 0
fi


echo -e "\e[1;34m\r\n2.start aes-128-ecb test\e[0m"

#hardware encrypt
./openssl aes-128-ecb -e -engine $dynamic_engine -base64 -in $1 -k 123456 -out h_aes_128_ecb_enc
#soft decrypt
./openssl aes-128-ecb -d -base64 -in h_aes_128_ecb_enc -k 123456 -out s_aes_128_ecb_dec
result=`diff $1 s_aes_128_ecb_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-128-ecb encrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-128-ecb encrypt test failed.\e[0m"
  exit 0
fi

#soft encrypt
./openssl aes-128-ecb -e -base64 -in $1 -k 123456 -out s_aes_128_ecb_enc
#hardware decrypt
./openssl aes-128-ecb -d -base64 -in s_aes_128_ecb_enc -engine $dynamic_engine -k 123456 -out h_aes_128_ecb_dec
result=`diff $1 h_aes_128_ecb_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-128-ecb decrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-128-ecb decrypt test failed.\e[0m"
  exit 0
fi


echo -e "\e[1;34m\r\n3.start aes-192-cbc test\e[0m"


#hardware encrypt
./openssl aes-192-cbc -e -base64 -in $1 -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_192_cbc_enc
#soft decrypt
./openssl aes-192-cbc -d -base64 -in h_aes_192_cbc_enc -iv 123456  -k 123456 -out s_aes_192_cbc_dec
result=`diff $1 s_aes_192_cbc_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-192-cbc encrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-192-cbc encrypt test failed.\e[0m"
  exit 0
fi

#soft encrypt
./openssl aes-192-cbc -e -base64 -in $1 -iv 123456 -k 123456 -out s_aes_192_cbc_enc
#hardware decrypt
./openssl aes-192-cbc -d -base64 -in s_aes_192_cbc_enc -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_192_cbc_dec
result=`diff $1 h_aes_192_cbc_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-192-cbc decrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-192-cbc decrypt test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n4.start aes-192-ecb test\e[0m"


#hardware encrypt
./openssl aes-192-ecb -e -base64 -in $1 -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_192_ecb_enc
#soft decrypt
./openssl aes-192-ecb -d -base64 -in h_aes_192_ecb_enc -iv 123456  -k 123456 -out s_aes_192_ecb_dec
result=`diff $1 s_aes_192_ecb_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-192-ecb encrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-192-ecb encrypt test failed.\e[0m"
  exit 0
fi

#soft encrypt
./openssl aes-192-ecb -e -base64 -in $1 -iv 123456 -k 123456 -out s_aes_192_ecb_enc
#hardware decrypt
./openssl aes-192-ecb -d -base64 -in s_aes_192_ecb_enc -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_192_ecb_dec
result=`diff $1 h_aes_192_ecb_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-192-ecb decrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-192-ecb decrypt test failed.\e[0m"
  exit 0
fi


echo -e "\e[1;34m\r\n5.start aes-256-cbc test\e[0m"


#hardware encrypt
./openssl aes-256-cbc -e -base64 -in $1 -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_256_cbc_enc
#soft decrypt
./openssl aes-256-cbc -d -base64 -in h_aes_256_cbc_enc -iv 123456  -k 123456 -out s_aes_256_cbc_dec
result=`diff $1 s_aes_256_cbc_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-256-cbc encrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-256-cbc encrypt test failed.\e[0m"
  exit 0
fi

#soft encrypt
./openssl aes-256-cbc -e -base64 -in $1 -iv 123456 -k 123456 -out s_aes_256_cbc_enc
#hardware decrypt
./openssl aes-256-cbc -d -base64 -in s_aes_256_cbc_enc -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_256_cbc_dec
result=`diff $1 h_aes_256_cbc_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-256-cbc decrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-256-cbc decrypt test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n6.start aes-256-ecb test\e[0m"


#hardware encrypt
./openssl aes-256-ecb -e -base64 -in $1 -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_256_ecb_enc
#soft decrypt
./openssl aes-256-ecb -d -base64 -in h_aes_256_ecb_enc -iv 123456  -k 123456 -out s_aes_256_ecb_dec
result=`diff $1 s_aes_256_ecb_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-256-ecb encrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-256-ecb encrypt test failed.\e[0m"
  exit 0
fi

#soft encrypt
./openssl aes-256-ecb -e -base64 -in $1 -iv 123456 -k 123456 -out s_aes_256_ecb_enc
#hardware decrypt
./openssl aes-256-ecb -d -base64 -in s_aes_256_ecb_enc -iv 123456 -engine $dynamic_engine -k 123456 -out h_aes_256_ecb_dec
result=`diff $1 h_aes_256_ecb_dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36maes-256-ecb decrypt test success.\e[0m"
else
  echo -e "\e[1;31maes-256-ecb decrypt test failed.\e[0m"
  exit 0
fi


echo -e "\e[1;32m\r\n-----------------------------------------aes test end.--------------------------------------------\e[0m"

echo -e "\e[1;32m\r\n----------------------------------------rsa encrypt(pkcs padding) test start.---------------------\e[0m"
echo -e "\e[1;34m\r\n1.start rsa1024 encrypt test\e[0m"
./openssl rsautl -encrypt -pkcs -in $1 -inkey test1024_pub.key -pubin -out test1024_s.enc
./openssl rsautl -decrypt -pkcs -in test1024_s.enc -inkey test1024.key -engine $dynamic_engine -out test1024_d.dec
result=`diff $1 test1024_d.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa1024 encrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa1024 encrypt test failed.\e[0m"
  exit 0
fi

./openssl rsautl -encrypt -pkcs -in $1 -inkey test1024_pub.key -engine $dynamic_engine -pubin -out test1024_d.enc
./openssl rsautl -decrypt -pkcs -in test1024_d.enc -inkey test1024.key -out test1024_s.dec
result=`diff $1 test1024_s.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa1024 decrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa1024 decrypt test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n2.start rsa2048 encrypt test\e[0m"
./openssl rsautl -encrypt -pkcs -in $1 -inkey test2048_pub.key -pubin -out test2048_s.enc
./openssl rsautl -decrypt -pkcs -in test2048_s.enc -inkey test2048.key -engine $dynamic_engine -out test2048_d.dec
result=`diff $1 test2048_d.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa2048 encrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa2048 encrypt test failed.\e[0m"
  exit 0
fi

./openssl rsautl -encrypt -pkcs -in $1 -inkey test2048_pub.key -engine $dynamic_engine -pubin -out test2048_d.enc
./openssl rsautl -decrypt -pkcs -in test2048_d.enc -inkey test2048.key -out test2048_s.dec
result=`diff $1 test2048_s.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa2048 decrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa2048 decrypt test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n3.start rsa4096 encrypt test\e[0m"
./openssl rsautl -encrypt -pkcs -in $1 -inkey test4096_pub.key -pubin -out test4096_s.enc
./openssl rsautl -decrypt -pkcs -in test4096_s.enc -inkey test4096.key -engine $dynamic_engine -out test4096_d.dec
result=`diff $1 test4096_d.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa4096 encrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa4096 encrypt test failed.\e[0m"
  exit 0
fi

./openssl rsautl -encrypt -pkcs -in $1 -inkey test4096_pub.key -engine $dynamic_engine -pubin -out test4096_d.enc
./openssl rsautl -decrypt -pkcs -in test4096_d.enc -inkey test4096.key -out test4096_s.dec
result=`diff $1 test4096_s.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa4096 decrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa4096 decrypt test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;32m\r\n------------------------------rsa encrypt(pkcs padding) test end.---------------------------------\e[0m"

echo -e "\e[1;32m\r\n----------------------------------------rsa encrypt(OAEP padding) test start.---------------------\e[0m"
echo -e "\e[1;34m\r\n1.start rsa1024 encrypt test\e[0m"
./openssl rsautl -encrypt -oaep -in $1 -inkey test1024_pub.key -pubin -out test1024_s.enc
./openssl rsautl -decrypt -oaep -in test1024_s.enc -inkey test1024.key -engine $dynamic_engine -out test1024_d.dec
result=`diff $1 test1024_d.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa1024 encrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa1024 encrypt test failed.\e[0m"
  exit 0
fi

./openssl rsautl -encrypt -oaep -in $1 -inkey test1024_pub.key -engine $dynamic_engine -pubin -out test1024_d.enc
./openssl rsautl -decrypt -oaep -in test1024_d.enc -inkey test1024.key -out test1024_s.dec
result=`diff $1 test1024_s.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa1024 decrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa1024 decrypt test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n2.start rsa2048 encrypt test\e[0m"
./openssl rsautl -encrypt -oaep -in $1 -inkey test2048_pub.key -pubin -out test2048_s.enc
./openssl rsautl -decrypt -oaep -in test2048_s.enc -inkey test2048.key -engine $dynamic_engine -out test2048_d.dec
result=`diff $1 test2048_d.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa2048 encrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa2048 encrypt test failed.\e[0m"
  exit 0
fi

./openssl rsautl -encrypt -oaep -in $1 -inkey test2048_pub.key -engine $dynamic_engine -pubin -out test2048_d.enc
./openssl rsautl -decrypt -oaep -in test2048_d.enc -inkey test2048.key -out test2048_s.dec
result=`diff $1 test2048_s.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa2048 decrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa2048 decrypt test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n3.start rsa4096 encrypt test\e[0m"
./openssl rsautl -encrypt -oaep -in $1 -inkey test4096_pub.key -pubin -out test4096_s.enc
./openssl rsautl -decrypt -oaep -in test4096_s.enc -inkey test4096.key -engine $dynamic_engine -out test4096_d.dec
result=`diff $1 test4096_d.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa4096 encrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa4096 encrypt test failed.\e[0m"
  exit 0
fi

./openssl rsautl -encrypt -oaep -in $1 -inkey test4096_pub.key -engine $dynamic_engine -pubin -out test4096_d.enc
./openssl rsautl -decrypt -oaep -in test4096_d.enc -inkey test4096.key -out test4096_s.dec
result=`diff $1 test4096_s.dec`
if [ ! -n "$result" ];then
  echo -e "\e[1;36mrsa4096 decrypt test success.\e[0m"
else
  echo -e "\e[1;31mrsa4096 decrypt test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;32m\r\n------------------------------rsa encrypt(OAEP padding) test end.---------------------------------\e[0m"


echo -e "\e[1;32m\r\n---------------------------------------rsa sign test start.---------------------------------------\e[0m"
echo -e "\e[1;34m\r\n1.start rsa1024 sign test\e[0m"
./openssl dgst -engine $dynamic_engine -sign test1024.key -sha256 -out test1024_s.sign $1
result=`./openssl dgst -verify test1024_pub.key -sha256 -signature test1024_s.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mrsa1024 sign test success.\e[0m"
else
  echo -e "\e[1;31mrsa1024 sign test failed.\e[0m"
  exit 0
fi

./openssl dgst -sign test1024.key -sha256 -out test1024_s.sign $1
result=`./openssl dgst -engine $dynamic_engine -verify test1024_pub.key -sha256 -signature test1024_s.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mrsa1024 verify test success.\e[0m"
else
  echo -e "\e[1;31mrsa1024 verify test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n2.start rsa2048 sign test\e[0m"
./openssl dgst -engine $dynamic_engine -sign test2048.key -sha256 -out test2048_s.sign $1
result=`./openssl dgst -verify test2048_pub.key -sha256 -signature test2048_s.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mrsa2048 sign test success.\e[0m"
else
  echo -e "\e[1;31mrsa2048 sign test failed.\e[0m"
  exit 0
fi

./openssl dgst -sign test2048.key -sha256 -out test2048_s.sign $1
result=`./openssl dgst -engine $dynamic_engine -verify test2048_pub.key -sha256 -signature test2048_s.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mrsa2048 verify test success.\e[0m"
else
  echo -e "\e[1;31mrsa2048 verify test failed.\e[0m"
  exit 0
fi


echo -e "\e[1;34m\r\n3.start rsa4096 sign test\e[0m"
./openssl dgst -engine $dynamic_engine -sign test4096.key -sha256 -out test4096_s.sign $1
result=`./openssl dgst -verify test4096_pub.key -sha256 -signature test4096_s.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mrsa4096 sign test success.\e[0m"
else
  echo -e "\e[1;31mrsa4096 sign test failed.\e[0m"
  exit 0
fi

./openssl dgst -sign test4096.key -sha256 -out test4096_s.sign $1
result=`./openssl dgst -engine $dynamic_engine -verify test4096_pub.key -sha256 -signature test4096_s.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mrsa4096 verify test success.\e[0m"
else
  echo -e "\e[1;31mrsa4096 verify test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;32m\r\n----------------------------------------rsa sign test end.----------------------------------------\e[0m"


echo -e "\e[1;32m\r\n--------------------------------------ecdsa sign test start.--------------------------------------\e[0m"
echo -e "\e[1;34m\r\n1.start ecdsa-p256k1 sign test\e[0m"

./openssl dgst -engine $dynamic_engine -sign ec256k1_priv.pem -sha256 -out testp256k1_h.sign $1
result=`./openssl dgst -verify ec256k1_pub.pem -sha256 -signature testp256k1_h.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mecdsa-p256k1 sign test success.\e[0m"
else
  echo -e "\e[1;31mecdsa-p256k1 sign test failed.\e[0m"
  exit 0
fi

./openssl dgst -sign ec256k1_priv.pem -sha256 -out testp256k1_s.sign $1
result=`./openssl dgst -engine $dynamic_engine -verify ec256k1_pub.pem -sha256 -signature testp256k1_s.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mecdsa-p256k1 verify test success.\e[0m"
else
  echo -e "\e[1;31mecdsa-p256k1 verify test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;34m\r\n2.start ecdsa-p256r1 sign test\e[0m"

./openssl dgst -engine $dynamic_engine -sign ec256r1_priv.pem -sha256 -out testp256r1_h.sign $1
result=`./openssl dgst -verify ec256r1_pub.pem -sha256 -signature testp256r1_h.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mecdsa-p256r1 sign test success.\e[0m"
else
  echo -e "\e[1;31mecdsa-p256r1 sign test failed.\e[0m"
  exit 0
fi

./openssl dgst -sign ec256r1_priv.pem -sha256 -out testp256r1_s.sign $1
result=`./openssl dgst -engine $dynamic_engine -verify ec256r1_pub.pem -sha256 -signature testp256r1_s.sign $1`
if [ "$result" = "Verified OK" ]; then
  echo -e "\e[1;36mecdsa-p256r1 verify test success.\e[0m"
else
  echo -e "\e[1;31mecdsa-p256r1 verify test failed.\e[0m"
  exit 0
fi

echo -e "\e[1;32m\r\n----------------------------------------ecdsa sign test end.--------------------------------------\e[0m"
