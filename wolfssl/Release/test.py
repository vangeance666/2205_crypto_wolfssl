# import socket


# if __name__ == '__main__':
#   remote_host = "www.youtube.com"
#   CON_PORT = 443
#   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	
#   s.connect((remote_host, CON_PORT))


#   # remote_host = "https://www.reddit.com/register/"

#   s.send("GET / HTTP/1.1\r\nHost: www.youtube.com\r\n\r\n".encode('utf-8'))

#   print("IP" + socket.gethostbyname(remote_host))
#   print(s.recv(4096))

#   s.close()
#   
#   
# import socket
# request = b"GET / HTTP/1.1\nHost: youtube.com\n\n"

# request2 = b"POST /youtubei/v1/search?key=AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8 HTTP/2\r\n Host: www.youtube.com\r\n Referer:https://www.youtube.com/results?search_query=send+socket \r\n\r\n"
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect(("youtube.com", 80))
# s.send(request)
# result = s.recv(10000)
# while (len(result) > 0):
#     print(result)
#     result = s.recv(10000) 


# import socket

# def get_certificate(host, port, cert_file_pathname):
	
# 	s = socket()
# 	context = SSL.Context(SSL.TLSv1_2_METHOD)
# 	print('Connecting to {0} to get certificate...'.format(host))
# 	conn = SSL.Connection(context, s)
# 	certs = []

# 	try:
# 		conn.connect((host, port))
# 		conn.do_handshake()
# 		certs = conn.get_peer_cert_chain()

# 	except SSL.Error as e:
# 		print('Error: {0}'.format(str(e)))
# 		exit(1)

# 	try:
# 		for index, cert in enumerate(certs):
# 			cert_components = dict(cert.get_subject().get_components())
# 			if(sys.version_info[0] >= 3):
# 				cn = (cert_components.get(b'CN')).decode('utf-8')
# 			else:
# 				cn = cert_components.get('CN')
# 			print('Centificate {0} - CN: {1}'.format(index, cn))

# 			try:
# 				temp_certname = '{0}_{1}.crt'.format(cert_file_pathname, index)
# 				with open(temp_certname, 'w+') as output_file:
# 					if(sys.version_info[0] >= 3):
# 						output_file.write((crypto.dump_certificate
# 										 (crypto.FILETYPE_PEM, cert).decode('utf-8')))
# 					else:
# 						output_file.write((crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
# 			except IOError:
# 				print('Exception:  {0}'.format(IOError.strerror))

# 	except SSL.Error as e:
# 		print('Error: {0}'.format(str(e)))
# 		exit(1)



# get_certificate("xsite.singaporetech.edu.sg", 443, "hehe")


from Crypto.PublicKey import RSA

print(RSA.__file__)

public_key = RSA.importKey(open('./certs/youtube/youtube-root.pem', 'r').read())

print(type(public_key))

print(public_key.n)