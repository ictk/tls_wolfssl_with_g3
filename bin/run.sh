export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/../reflib/gnu-armhf
echo $LD_LIBRARY_PATH
./neo_wolf_ssl -h localhost  -p 8883  -l ECDHE-ECDSA-AES128-SHA256

