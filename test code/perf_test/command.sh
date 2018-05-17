echo "1 process:" > hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "5 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 5 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 5 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "10 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 10 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 10 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "20 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 20 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 20 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "40 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 40 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 40 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "70 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 70 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 70 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "110 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 110 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 110 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "160 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 160 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 160 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "200 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 200 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 200 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "250 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 250 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 250 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "500 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 500 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 500 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt

echo "1000 process:" >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 1000 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> hardware.txt
./openssl speed -elapsed -engine ./libeng_cryptodev.so -multi 1000 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> hardware.txt
echo -e "\n" >> hardware.txt
