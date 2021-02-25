
#ifndef junkstobedeleted_h
#define junkstobedeleted_h
#define SIT_FLDR "./certs/sit/"


#define SIT_CHAIN SIT_FLDR "singaporetech-chain.pem"
#define SIT_ROOT SIT_FLDR "singaporetech-root.pem"
#define SIT_GET "GET / HTTP/1.1\r\nHost: www.singaporetech.edu.sg\r\n\r\n"
#define SIT_POST "POST / HTTP/1.1\r\nHost: www.singaporetech.edu.sg\r\n\r\n"

//Pass
#define INSTA_HOST "instagram.com"
#define INSTA_FLDR "./certs/instagram/"
#define INSTA_ROOT INSTA_FLDR "instagram-root.pem"
#define INSTA_CHAIN INSTA_FLDR "instagram-chain.pem"
#define INSTA_GET "GET / HTTP/1.1\r\nHost: instagram.com\r\n\r\n"
#define INSTA_POST "POST / HTTP/1.1\r\nHost: instagram.com\r\n\r\n"


#define SITCN_FLDR "./certs/sitcn/"
#define SITCN_CHAIN SITCN_FLDR "sitcn-chain.pem"
#define SITCN_ROOT SITCN_FLDR "sitcn-root.pem"
#define SITCN_GET "GET / HTTP/1.1\r\nHost: sitcn2021.singaporetech.edu.sg\r\n\r\n"

//pass
#define REDDIT_HOST "reddit.com"
#define REDDIT_FLDR "./certs/reddit/"
#define REDDIT_ROOT REDDIT_FLDR "reddit-root.pem"
#define REDDIT_MID REDDIT_FLDR "reddit-mid.pem"
#define REDDIT_SERV REDDIT_FLDR "reddit-server.pem"
#define REDDIT_CHAIN REDDIT_FLDR "reddit-chain.pem"
#define REDDIT_GET2 "GET /register/ HTTP/2\r\nHost: www.reddit.com \r\n\r\n"
#define REDDIT_GET "GET / HTTP/1.1\r\nHost: www.reddit.com \r\n\r\n"
#define REDDIT_POST "POST / HTTP/1.1\r\n Host: www.reddit.com \r\n\r\n"


#define SOF_FLDR "./certs/stackoverflow/"
#define SOF_ROOT SOF_FLDR "sof-root.pem"
#define SOF_MID SOF_FLDR "sof-mid.pem"
#define SOF_SERV SOF_FLDR "sof-server.pem"
#define SOF_CHAIN  SOF_FLDR "sof-chain.pem"
#define SOF_GET "GET / HTTP/1.1\r\nHost: stackoverflow.com\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n"

#define XSITE_FLDR "./certs/xsite/"
#define XSITE_ROOT XSITE_FLDR "xsite-root.pem"
#define XSITE_MID XSITE_FLDR "xsite-mid.pem"
#define XSITE_SERV XSITE_FLDR "xsite-server.pem"
#define XSITE_CHAIN  XSITE_FLDR "xsite-chain.pem"
#define XSITE_GET_OLD "GET /d2l/lp/auth/saml/login HTTP/2\r\nHost: xsite.singaporetech.edu.sg \r\n\r\n"
#define XSITE_GET "GET /d2l/loginh/js/main.js HTTP/1.1\r\nHost: xsite.singaporetech.edu.sg\r\n\r\n"

//Pass
#define SLACK_HOST "slack.com"
#define SLACK_FLDR "./certs/slack/"
#define SLACK_GET "GET / HTTP/1.1\r\nHost: slack.com\r\n\r\n"
#define SLACK_POST "POST / HTTP/1.1\r\nHost: slack.com\r\n\r\n"
#define SLACK_ROOT SLACK_FLDR "slack-root.pem"

//Pass
#define YT_HOST "youtube.com"
#define YT_FLDR "./certs/youtube/"
#define YT_ROOT YT_FLDR "youtube-root.pem"
#define YT_MID YT_FLDR "youtube-mid.pem"
#define YT_SERV YT_FLDR "youtube-server.pem"
#define YT_CHAIN  YT_FLDR "youtube-chain.pem"
#define YT_GET "GET / HTTP/1.1\r\nHost: www.youtube.com\r\n\r\n"

#define YT_POST "POST / HTTP/1.1\r\nHost: youtube.com\r\n\r\n"
//Full one cycle reference
//static int server_interact(const char *certPath, const char *certFldr,
//	const char *sendMsg, const char *servHostName, const int portNo) {
//
//
//	printf("SendMsg:\n%s \n", sendMsg);
//
//	struct sockaddr_in servAddr;
//	SOCKET_T sockfd; WOLFSSL *ssl;
//
//	char servResponse[BUFF_SIZE], servIp[IP_BUFF_SIZE];
//	int ret, suc, err; size_t i;
//
//	WOLFSSL_CTX *ctx;
//
//	if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL)
//		eprintf("Failed to create WolfSSL context.\n", ctx_cleanup);
//	if ((ret = wolfSSL_CTX_load_verify_locations(ctx, certPath, certFldr)) != SSL_SUCCESS)
//		eprintf("Failed to load cert file.\n", finish);
//
//	///////////////////////////////
//
//	if (!host_to_ip(servHostName, servIp))
//		eprintf("Unable to convert hostname to IP Address.\n", finish)
//	else
//		printf("Converted Hostname to IP Address: %s .\n", servIp);
//
//	// Proceed with setting up socket details
//	sockfd = socket(AF_INET, SOCK_STREAM, 0);
//	memset(&servAddr, 0, sizeof(servAddr));
//
//	// Configure server details
//	servAddr.sin_family = AF_INET;
//	servAddr.sin_port = htons(portNo);
//	servAddr.sin_addr.s_addr = inet_addr(servIp);
//
//	if (connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)) == -1)
//		eprintf("Failed to connect to socket\n", socket_cleanup)
//
//		//tcp_connect(&sockfd, host, port, dtlsUDP, dtlsSCTP, ssl);
//		// Load and verify the certs
//
//
//		if ((ssl = wolfSSL_new(ctx)) == NULL)
//			eprintf("Failed to load SSL struct.\n", ssl_cleanup)
//
//			if (wolfSSL_set_fd(ssl, sockfd) != SSL_SUCCESS)
//				eprintf("Failed to attach wolfssl to socket.\n", ssl_cleanup)
//
//				if (wolfSSL_check_domain_name(ssl, servHostName) == WOLFSSL_SUCCESS)
//					printf("SSl Domain Check Pass.\n\n");
//				else
//					eprintf("Failed cert domain check.\n", ssl_cleanup)
//
//					if ((ret = wolfSSL_connect_cert(ssl)) != WOLFSSL_SUCCESS) {
//						err = wolfSSL_get_error(ssl, 0);
//						printf("WOLFSSL Connect Error No: %d\n", err);
//						if (err == -188)
//							printf("[Error] ASN sig error, no CA signer to verify certificate.\n");
//						eprintf("Failed wolfSSL_connect().\n", ssl_cleanup)
//					}
//
//	(void)ClientWrite(ssl, sendMsg, strlen(sendMsg), "", 1);
//
//	for (i = 1; i; i = ClientRead(ssl, servResponse, sizeof(servResponse) - 1, 1, "", 1));
//
//	printf("===%s Respond===\n %s\n", servHostName, servResponse);
//
//	suc = 1;
//
//	//ssl = wolfSSL_new(ctx);
//ssl_cleanup:
//	wolfSSL_free(ssl);
//socket_cleanup:
//	close(sockfd);
//
//ctx_cleanup:
//	wolfSSL_CTX_free(ctx);
//finish:
//	return suc;
//}

#endif
