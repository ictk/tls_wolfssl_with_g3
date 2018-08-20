# Notes - Please read

## Note 1
```
tls_wolfssl_with_g3 is project about tls communication with g3 chip(ictk co,. cryptto puf chip) from wolfssl 3.12.
This project is limited to tls1.2 and cipher suite ECDHE-ECDSA-AES128-SHA256.



## How To BUILD

### library build
```
1.>cd libneo_wolf_ssl
2.write PLATFORM=[platform] in Makefile 
	default PLATFORM=gnu-armhf
	'gnu-armhf' is raspberry cpu 
	
3.>make
```

### excute file  build
```
1.>cd console_neo_wolf_ssl
2.write PLATFORM=[platform] in Makefile 
	default PLATFORM=gnu-armhf
	'gnu-armhf' is raspberry cpu 
	
3.>make
```

### tls setup   build
```
1.>cd etc/tls_setup
2.write PLATFORM=[platform] in Makefile 
	default PLATFORM=gnu-armhf
	'gnu-armhf' is raspberry cpu 
	
3.>make
```


## HOW TO SAMPLE RUN

### tls setup(provisioning)
```
1.connect on ievb-100 device
2.>cd bin
3.>./tls_setup.sh
```

###  run server 
```
1.>cd etc/tls_server
2.change tls server info on run.sh
nohup ./tls_server.py -cp ./certs -p [SERVER PORT] -cr CERT_REQUIRED -r ca.crt&
3.>./run_server.sh
```


### run client
```
1.connect on ievb-100 device
2.>cd bin
3.change tls server info on run.sh
./neo_wolf_ssl -h [SERVER ADDRESS]  -p [SERVER PORT]  -l ECDHE-ECDSA-AES128-SHA256
4.>./run.sh
```



