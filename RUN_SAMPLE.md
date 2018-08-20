* tls setup(provisioning)
1.connect on ievb-100 device
2.>cd bin
3.>./tls_setup.sh


* run server 
1.>cd etc/tls_server
2.change tls server info on run.sh
nohup ./tls_server.py -cp ./certs -p [SERVER PORT] -cr CERT_REQUIRED -r ca.crt&
3.>./run_server.sh



* run client
1.connect on ievb-100 device
2.>cd bin
3.change tls server info on run.sh
./neo_wolf_ssl -h [SERVER ADDRESS]  -p [SERVER PORT]  -l ECDHE-ECDSA-AES128-SHA256
4.>./run.sh







