export PYTOOL_PATH=${HOME}/PYTOOL
export PYTHONPATH=${PYTHONPATH}:${PYTOOL_PATH}
export PRJ_PATH=$PYTOOL_PATH/ictk_project/giant_3
nohup python3 tls_server.py -option tls_server -cp ./certs -p 8883 -cr CERT_REQUIRED -r ca.crt &
