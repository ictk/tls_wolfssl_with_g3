set PYTHONPATH=%cd%
python.exe tls_server.py -cp ./certs -p 8883 -cr CERT_REQUIRED -r ca.crt 
pause