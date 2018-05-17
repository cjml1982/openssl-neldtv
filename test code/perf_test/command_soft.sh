echo "1 process:" > software.txt
openssl speed -elapsed  rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "5 process:" >> software.txt
openssl speed -elapsed  -multi 5 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 5 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "10 process:" >> software.txt
openssl speed -elapsed  -multi 10 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 10 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "20 process:" >> software.txt
openssl speed -elapsed  -multi 20 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 20 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "40 process:" >> software.txt
openssl speed -elapsed  -multi 40 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 40 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "70 process:" >> software.txt
openssl speed -elapsed  -multi 70 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 70 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "110 process:" >> software.txt
openssl speed -elapsed  -multi 110 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 110 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "160 process:" >> software.txt
openssl speed -elapsed  -multi 160 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 160 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "200 process:" >> software.txt
openssl speed -elapsed  -multi 200 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 200 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "250 process:" >> software.txt
openssl speed -elapsed  -multi 250 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 250 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "500 process:" >> software.txt
openssl speed -elapsed  -multi 500 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 500 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt

echo "1000 process:" >> software.txt
openssl speed -elapsed  -multi 1000 rsa1024 rsa2048 rsa4096 | grep -E "bits|nistp256" | tr -s ' ' | cut -d ' ' -f 1,2,3,6,7 >> software.txt
openssl speed -elapsed  -multi 1000 ecdsap256 | grep nistp256 | tr -s ' ' | cut -d ' ' -f 2,3,4,8,9 >> software.txt
echo -e "\n" >> software.txt
