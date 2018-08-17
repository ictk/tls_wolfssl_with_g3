import socket, ssl, pprint
import argparse
#from neolib.hexstr_util import *

def do_something(connstream, data):
	print("do_something:", data)
	connstream.write(data)
	return False

def deal_with_client(connstream):
	#data = connstream.read()
	#print(data)
	while True:
		data = connstream.read()
		msg = "G3 PUF IS THE BEST!!!!!!!!!!!!!!!!!!!!! "
		print("RECV:",data.decode())
		print("SEND:", msg)
		print()
		print()
		connstream.write(msg.encode())

		#do_something(connstream, msg.encode())
		# if not do_something(connstream, "PUF IS BEST SOLUTION FOR SECURITY ".encode()):
		# 	break

		#print(data)


def main():
	print('server start')
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", "--port", action="store", dest="port", help="port", default="1350")
	parser.add_argument("-cp", "--cert_path", action="store", required=True, dest="cert_path", help="path for keys")

	parser.add_argument("-c", "--cert", action="store", dest="cert", default="server.crt", help="Certificate file path")
	parser.add_argument("-k", "--key", action="store", dest="key", default="server.key", help="Private key file path")
	parser.add_argument("-cr", "--cert_request", action="store", dest="cert_request", default="CERT_NONE",
	                    help="certification request ")
	parser.add_argument("-r", "--rootCA", action="store", dest="root_ca", help="Root CA file path")

	args = parser.parse_args()
	port = int(args.port)
	cert_path = args.cert_path
	root_ca = args.root_ca if args.root_ca == None else cert_path + "/" + args.root_ca
	cert = cert_path + "/" + args.cert
	key = cert_path + "/" + args.key

	cert_request = getattr(ssl, args.cert_request.upper())
	# ssl.CERT_NONE if  =='N' else  ssl.CERT_REQUIRED

	print('port:', port)
	print('cert_path:', cert_path)
	print('root_ca:', root_ca)
	print('cert:', cert)
	print('key:', key)
	print('cert_request:', cert_request)

	bindsocket = socket.socket()
	print('server bindingg')
	bindsocket.bind(('0.0.0.0', port))

	bindsocket.listen(5)


	while True:
		print('server waiting')
		newsocket, fromaddr = bindsocket.accept()
		print('server accept ',newsocket, fromaddr)

		try:
			connstream = ssl.wrap_socket(newsocket,
			                             server_side=True,
			                             certfile=cert,
			                             keyfile=key,
			                             cert_reqs=cert_request,
			                             ca_certs=root_ca,

			                             # certfile="../cert/lesstif.com.crt",
			                             #      keyfile="../cert/lesstif.com.key"
			                             )

			# connstream.context.set_ciphers('ECDHE-ECDSA-AES128-SHA256')
	#		print(connstream.context.get_ciphers())

			print(repr(connstream.getpeername()))
			print(connstream.cipher())
			print(pprint.pformat(connstream.getpeercert()))

			deal_with_client(connstream)

			connstream.shutdown(socket.SHUT_RDWR)
			connstream.close()

		except Exception as ext:
			print(ext)

if __name__ == "__main__":
	main()
	pass
