export PYTOOL_PATH=${HOME}/PYTOOL
export PYTHONPATH=${PYTHONPATH}:${PYTOOL_PATH}
python3 tls_server.py -cp ./certs -p 8883 -cr CERT_REQUIRED -r ca.crt 
