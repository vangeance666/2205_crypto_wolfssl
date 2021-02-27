#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

#include <curl/curl.h>
// Makes all SSL header to include our defined settings user_settings.h
#define WOLFSSL_USER_SETTINGS 

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>


#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>

// Need these 3 to enable OCSP for cert manager
#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/x509v3.h>

// Our functions and declarations (Sequence matters)
#include "globals.h"
#include "common.h"
#include "certfields.h"
#include "callbacks.h"
#include "requests.h"
#include "verify.h"
#include "junkstobedeleted.h" //Delete once everything sui

#define BUFFER_SIZE 2048

#define HEADER_SIZE 8192

#define CLI_MSG_SZ      32
#define CLI_REPLY_SZ    256

#define crlPemDir "../../certs/crl"

#define MOZILLA_ROOT "./certs/mozilla-roots-cas.pem"

#define FLD_ENDLN "\r\n"
#define FLD_FINISH FLD_ENDLN FLD_ENDLN
#define HDR_HTTP "HTTP/1.1"
#define HDR_HOST "Host:"
#define HDR_POST "POST"
#define HDR_GET "GET"

#define RESPONSE_FILE "temp_server_response.txt"

typedef struct sockaddr_in  SOCKADDR_IN_T;

typedef enum {
	ADDR_DEFAULT = -100,
	ADDR_SUCESS,
	ADDR_WSA_FAIL,
	ADDR_INVALID_ADDR_PTR,
	ADDR_INVALID_PEER_IP
} addr_ret_t;

typedef enum {
	TCP_DEFAULT = -150,
	TCP_SUCESS,
	TCP_ADDR_FAIL,
	TCP_CONNECT_FAIL
}tcp_ret_t;

typedef enum {
	SES_DEFAULT = -200,
	SES_SUCESS,
	SES_WOLF_INIT_FAIL,
	SES_CTX_FAIL,
	SES_SSL_FAIL,
	SES_CA_LOAD_FAIL,
	SES_SOCKET_FAIL,
	SES_FD_FAIL,
	SES_DOMAIN_CHECK_FAIL,
	SES_HANDSHAKE_FAIL,
	SES_READ_RESP_FAIL,
	SES_RESP_BAD_SAVE_FILE
} ses_ret_t;

static char request[] = "";
char *createReq(char type[], char url[], char para[]);

static char *build_msg_header(const char *iType, const char *iUrl, const char *args, char *outBuffer);

int main(int argc, char **argv)
{

	//char *cut;
	//cut = str_slice_copy(fullStr, 5, 10); // Will extract 5 to 9
	//int i;

	//printf("CUT: %s\n", cut);

	//free(cut);



	int ret;
	int saveResponseToFile = 1;
	//char input[MAX_INPUT];
	const char *type = NULL;
	const char *url = NULL;
	const char *para = "";

	char request[1000];
	memset(request, 0, sizeof(request)); 
	//build_msg_header("GET", "youtube.com/results", "search_query=ihate+school", request); fprintf(stdout, "%s\n", request); // Works
	build_msg_header("POST", "youtube.com/results", "search_query=ihate+school&test1=gogo&test2=fa", request); fprintf(stdout, "%s", request); // Works
	//build_msg_header("GET", "reddit.com", 0, request); fprintf(stdout, "%s\n", request); // Works


	/*build_msg_header("POST", "www.youtube.com", "hehe=1\r\ndog=41\r\nxyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("POST", "https://www.youtube.com", "hehe=1\r\ndog=41\r\nxyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("POST", "http://www.youtube.com", "hehe=1\r\ndog=41\r\nxyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "https://www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("POST", "http://www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "http://www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "http://www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "http://www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "http://www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "http://www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "http://www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));
	build_msg_header("GET", "http://www.youtube.com", "hehe=1&dog=41&xyou=414", request); fprintf(stdout, "%s\n", request); memset(request, 0, sizeof(request));*/
	//printf(YT_GET);

	//printf("%s\n", request);

	//ret = start_session(request, "youtube.com", HTTPS_PORT, saveResponseToFile);

	//checks if input exist, kind of 
	if (argc > 2) {
		//type = argv[1]; //GET or POST
		//url = argv[2];	//<url>/<path1>/<path2>
		//para = argv[3]; //parameter=value
		//printf("type = %s , url = %s , para = %s \n",type,url,para);
		//create request, scroll all the way down to see function
		

		//printf("Request: %s\n", request);

		//query request?
		//ret = start_session(request, url, HTTPS_PORT);
	}
	
	/////////////////
	//Usage for seeing message across.
	/*ret = start_session(YT_GET, "youtube.com", HTTPS_PORT);

	// Usage for seeing message across.
	ret = start_session(YT_GET, "youtube.com", HTTPS_PORT);
	//ret = start_session(REDDIT_GET, "reddit.com", HTTPS_PORT);

	//test_crl();
	//start_session("youtube.com", VERIFY_OVERRIDE_DATE_ERR);
	//cert_show_details(ENC_RSA, YT_ROOT);

	test_crl();
	start_session("youtube.com", VERIFY_OVERRIDE_DATE_ERR);
	cert_show_details(ENC_RSA, YT_ROOT);*/

	//print_help();
	//int end = 0;
	//
	//printf("\n\n");
	//printf("Input ur choice: ");

	//fgets(input, MAX_INPUT, stdin);

	///* Can modify program to be like arg parser but thats for later. */

	//if (_IS("1"))	// 1. View Youtube cert publickey info.
	//	cert_show_details(YT_ROOT);
	//if (_IS("2"))	//2. View Reddit cert publickey info.
	//	cert_show_details(REDDIT_ROOT);

	//if (_IS("3"))	//3. Youtube certs verification.
	//	if ((ret = cert_manual_verify(YT_ROOT, YT_MID))) fprintf(stdout, "Return Code: %d\n", ret);
	//if (_IS("4"))	//4. Reddit cert verifications.
	//	if ((ret = cert_manual_verify(REDDIT_MID, REDDIT_SERV))) fprintf(stdout, "Return Code: %d\n", ret);

finish:
	return ret;
}

static void print_help() {
	printf("Please select the following choices: \n");
	//printf("-------- Viewing Website certifications --------");
	printf("1. View Youtube cert publickey info.\n");
	printf("2. View Reddit cert publickey info.\n");
	//printf("-------- Verification of CA Certs --------");
	printf("3. Youtube certs verification.\n");
	printf("4. Reddit cert verifications.\n");
	//printf("-------- Write GET request to sites --------");

}

static void print_boarder(const char *c) {
	printf("------ %s ------\n", c);
}


static int print_cert_details(WOLFSSL_X509 *cert) {
	if (cert) {
		print_boarder("Cert X509 Info");
		show_x509_info(cert);
		print_boarder("Cert Full BIO with (N & E)");
		show_x509_bio_info(cert);
		print_boarder("Cert NAME Info");
		show_x509_name_info(cert);
		print_boarder("Cert Pubkey in Hex");
		show_pkey_details(cert);
	}
	else {
		fprintf(stderr, "Cert invalid pointer\n");
		return 0;
	}	
	return 1;
}


/**
 * Takes in a cert file to print details as
 * part of crypto project requirements.
 * 
 * @param  certPath File path of PEM cert
 * @return          1 if success, else 0
 */
static int cert_show_details(const char *certPath) {

	int suc;
	WOLFSSL_X509 *cert = (WOLFSSL_X509*)wolfSSL_Malloc(DYNAMIC_TYPE_X509);	

	// 1 Load cert from file
	if ((cert = wolfSSL_X509_load_certificate_file(certPath, SSL_FILETYPE_PEM)) == NULL){
		eprintf("Unable to load cert file to memory.\n", cleanup);
	}

	suc = print_cert_details(cert);	

cleanup:	
	XFREE(cert, 0, DYNAMIC_TYPE_X509);
finish:

	return suc;
}


/**
 * Helper function for setting up socket.
 * 
 * @param  addr SOCKADDR_IN_T object
 * @param  peer IP Address/Hostname of server
 * @param  port Port number to connect using
 * @return      Session Enum Code <addr_ret_t>
 */
static int build_addr(SOCKADDR_IN_T *addr, const char *peer, word16 port) {

	if (addr == NULL) 
		return ADDR_INVALID_ADDR_PTR;	

	int res;	
	WSADATA wsaData;
	struct hostent *entry;

	//For windows this one is required for gethostbyname to work
	if ((res = WSAStartup(MAKEWORD(2, 2), &wsaData)) != NULL) 
		return ADDR_WSA_FAIL;

	// Make it all null first
	XMEMSET(addr, 0, sizeof(SOCKADDR_IN_T));

	entry = gethostbyname(peer);
	//Set IP address to first IP using lookup
	if (entry) {
		XMEMCPY(&addr->sin_addr.s_addr, entry->h_addr_list[0],
			entry->h_length);
	} else {		
		if (is_valid_ip(peer))
			addr->sin_addr.s_addr = inet_addr(peer);
		else 
			return ADDR_INVALID_PEER_IP;		
	}

	addr->sin_family = AF_INET;
	addr->sin_port = XHTONS(port);

	return ADDR_SUCESS;
}



/**
 * Helper function to establish socket connect
 * to server. 
 * @param  sockfd Socket Object
 * @param  ip     Server's IP Address/Hostname in string
 * @param  port   Server's Port Number to connect
 * @param  ssl    wolfSSL session object
 * @return        Session Enum status code <tcp_ret_t>
 */
static int tcp_connect(SOCKET_T *sockfd, const char *ip, word16 port, WOLFSSL *ssl) {
	// Build addr Object first using IP/Hostname
	SOCKADDR_IN_T addr;
	if (!build_addr(&addr, ip, port))
		return TCP_ADDR_FAIL;

	*sockfd = socket(AF_INET, SOCK_STREAM, 0);	

	if (connect(*sockfd, (struct sockaddr*) &addr, sizeof(addr)) != 0)
		return TCP_CONNECT_FAIL;//eprintf("Failed to connect to socket\n", socket_cleanup)
	return TCP_SUCESS;
}


/**
 * Helper function to conduct ssl handshake 
 * within session.

 * @param  ssl WOLFSSL Object Ptr 
 * @return     If success 1, else 0
 */
static int connect_handshake(WOLFSSL *ssl) {
	int err, ret;
	do {
		err = 0; /* reset error */
		ret = wolfSSL_connect(ssl);
		if (ret != WOLFSSL_SUCCESS) {
			err = wolfSSL_get_error(ssl, 0);
		}
	} while (err == WC_PENDING_E);
	if (ret != WOLFSSL_SUCCESS) {
		fprintf(stderr, "SSL_connect failed %d %d\n", ret, err);
	}
	return ret;
}


/**
 * Single round of establish sesesion. Can be called
 * multiple rounds to simulate browser?
 * 
 * @param  ctx      WolfSSL Context
 * @param  zmsg     GET/POST message to send
 * @param  hostname Server IP Address/Hostname
 * @param  port     Port Number to connect using socket
 * @param  outMsg   Buffer to store server reply
 * @param  outMsgSz Buffer Size
 * @param  saveResponse 1 to save server GET/POST Response to a local file
 * @return          Session enum status code <ses_ret_t>
 */
static ses_ret_t new_session(WOLFSSL_CTX *ctx, const char *zmsg, 
	const char *hostname, word16 port,
	char *outMsg, int outMsgSz, FILE *saveFilePtr) {

	WOLFSSL *ssl;
	size_t	i; int err;

	tcp_ret_t	tcpRet;
	ses_ret_t	retCode = SES_DEFAULT;	

	SOCKET_T	sockfd;

	tcpRet = tcp_connect(&sockfd, hostname, port, ssl);

	if (tcpRet != TCP_SUCESS) {
		retCode = SES_SOCKET_FAIL;
		switch (tcpRet) {
			case TCP_ADDR_FAIL:
				eprintf("Unable to build addr for socket", socket_cleanup)
			case TCP_CONNECT_FAIL:
				eprintf("Unable to connect to socket", socket_cleanup)
		}
	}
	
	// New session always starts with this usage, replace ssl. reuse ctx
	if ((ssl = wolfSSL_new(ctx)) == NULL) {
		retCode = SES_SSL_FAIL;
		eprintf("Failed to start new session", ssl_cleanup);
	}		

	//Attach the socket to ssl session
	if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS) {
		retCode = SES_FD_FAIL;
		eprintf("Failed to attach socket to session", socket_cleanup);		
	}
		
	if (wolfSSL_check_domain_name(ssl, hostname) != WOLFSSL_SUCCESS) {
		retCode = SES_DOMAIN_CHECK_FAIL;
		eprintf("Failed cert domain check fail", socket_cleanup);
	}

	// Handshakel using WolfSSL_connect
	if (connect_handshake(ssl) != WOLFSSL_SUCCESS) {
		retCode = SES_HANDSHAKE_FAIL;
		eprintf("TCP Handshake fail", socket_cleanup);
	} 
	// Send Message over


	(void)ClientWrite(ssl, zmsg, strlen(zmsg), "", 1);

	int checkFinish = -1;
	
	int s = 0;
	do {
		printf("checkFinish:%d\n", checkFinish);
		if ((err = ClientRead(ssl, outMsg, outMsgSz, 1, &checkFinish, saveFilePtr)) != 0) {
			retCode = SES_READ_RESP_FAIL;
			eprintf("Encoutnered error when conducting wolfSSL_read()", socket_cleanup);
		}
		//printf("s: %d\n", s);
		++s;
	} while (checkFinish != 1);
	printf("out already ------ checkFinish:%d\n", checkFinish);
	
	/*if (saveFilePtr) printf("havefile\n");
	

	//for (i = 0; i < outMsgSz; ++i) {
	//	printf("%c", outMsg[i]);
	//}

	//fprintf(stdout, "Finished all:\n\n%s\n", outMsg);
	/*printf("Peek:%d\n", wolfSSL_peek(ssl, outMsg, outMsgSz));*/

	
	//printf("Ispending:%d\n", wolfSSL_pending(ssl));

	

socket_cleanup:
	CloseSocket(sockfd);
ssl_cleanup:
	wolfSSL_shutdown(ssl);
	wolfSSL_free(ssl);
finish:
	return retCode;
}


/**
 * Single usage of sending one message over to 
 * server. Mozilla CA cert store will be use for
 * verifying peer certificates. 
 * 
 * @param  zmsg GET/POST Message
 * @param  host Hostname or IP Address of Server
 * @param  port Port number to connect using socket
 * @return      Session Enum Code <ses_ret_t>
 */
static int start_session(const char *zmsg, const char *host, word16 port, int saveResponse) {

	ses_ret_t retCode;

	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		retCode = SES_WOLF_INIT_FAIL; 
		eprintf("WolfSSL_Init failed", wolf_cleanup);
	}
			
	WOLFSSL_CTX		*ctx;
	FILE *saveResponseFile;
	
	/* Init Session */
	if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
		retCode = SES_CTX_FAIL; 
		eprintf("Failed to setup wolfSSL Context", ctx_cleanup);
	}

	// Load in store of CA certs into cert manager so wolfSSL auto verify peer cert. 
	if (wolfSSL_CTX_load_verify_locations(ctx, MOZILLA_ROOT, 0) != SSL_SUCCESS) {
		retCode = SES_CA_LOAD_FAIL; 
		eprintf("Failed to load CA Certs from "MOZILLA_ROOT".", ctx_cleanup);
	}
	/* End of init Session*/
	
	// Set to always verify peer, will goto callback no matter what. (Uncomment once needed)
	wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, 0);

	// This one will affect  wolfSSL_pending's evaluation. Buffer size if 10000 it wont work idkwhy
	char serverResponse[10000]; 
	if (saveResponse) {
		saveResponseFile = fopen(RESPONSE_FILE, "w");
		if (saveResponseFile) {
			/* Start one one session */
			retCode = new_session(ctx, zmsg, host, port, serverResponse,
				sizeof(serverResponse), saveResponseFile);
			/* End of one session */

		} else {
			retCode = SES_RESP_BAD_SAVE_FILE;
			eprintf("Unable to open save file", file_cleanup);
		}		
	} else 
		retCode = new_session(ctx, zmsg, host, port, serverResponse,
			sizeof(serverResponse), 0);
	
	//printf("serverResponse: \n%s\n", serverResponse);
		
file_cleanup:
	if (saveResponseFile) fclose(saveResponseFile);
ctx_cleanup:
	wolfSSL_CTX_free(ctx);
wolf_cleanup:
	wolfSSL_Cleanup();
finish:
	return retCode;
}

static char *build_msg_header(const char *iType, const char *iUrl, const char *args, char *outBuffer) {
#define SET_FIRST_CUT(X) \
if (offset == -1) { \
offset = str_index(X, iUrl, 1); \
cutSz = sizeof(X) - 1; \
}	
#define _J(X) strcat(outBuffer, X);

	// Check if is not empty
	if (!iType || !iUrl) {
		printf("Type and URL cant be empty, args Optional\n");
		return 0; //Type and URL cant be empty, args Optional
	}

	size_t i; 
	const char *sz, *cut, *host, *path, *p;
	char buf[BUFFER_SIZE] = "";
	/* Start of extracting host and path */
	int offset = -1, cutSz = -1, firstSlashOffset = -1, ret;	
	
	SET_FIRST_CUT("https://www.");
	SET_FIRST_CUT("http://www.");
	SET_FIRST_CUT("www.");

	for (sz = iUrl; *sz; ) ++sz; 

	/*printf("iUrl:%s\noffset %d\ncutSZ:%d\n", iUrl, offset, cutSz);
	printf("(sz - iUrl):%d\n", (sz - iUrl));*/
	// If not default value means manage to find cut from above checks
	cut = (offset != -1)
		? str_slice_copy(iUrl, cutSz, (sz - iUrl))
		: str_alloc_copy(iUrl);

	/* URL will split into hostname and path. */
	if (cut) {		
		for (sz = cut; *sz; ) ++sz; // Use Sz to get ending of cut
		firstSlashOffset = str_index("/", cut, 0);
		if (firstSlashOffset != -1) {
			host = str_slice_copy(cut, 0, firstSlashOffset); // Host slice till before '/' offset
			path = str_slice_copy(cut, firstSlashOffset, sz - (cut)); // Host 
		}
		else {
			host = str_alloc_copy(cut); // No slash means cut already is host
			path = str_alloc_copy("/"); // If no slash treat path as /
		}
	}
	else 
		goto cleanup;
	/* End of parsing hostname and path */
	
	if (str_eq(HDR_POST, iType, 1)) {
		if (args) {
			int beforeIndex = 0, curIndex = 0;
			// Self parse, strcat buggy cant seem to work
			for (p = args; *p; ++p) {
				if (*p == '&') {
					for (i = beforeIndex; i < (p - args); )
						buf[curIndex++] = args[i++];
					buf[curIndex++] = '\r';
					buf[curIndex++] = '\n';
					beforeIndex = (p - args) + 1;
				}
			} for (i = beforeIndex; i < (p - args); buf[curIndex++] = args[i++]);				
		}
		// Start forming the request
		_J("POST ")	_J(path)_J(" "HDR_HTTP" "FLD_ENDLN)
		_J(HDR_HOST" www.")_J(host)_J(FLD_ENDLN)
		if (args) { _J(buf)_J(FLD_FINISH) } else { _J(FLD_ENDLN) }		
		//if (args) { _J(args)_J(FLD_FINISH) } else { _J(FLD_ENDLN) }		
		ret = 1;
	} else if (str_eq("GET", iType, 1)) {
		_J("GET ")_J(path) if (args) { if (*args != '?') { _J("?")_J(args) } else { _J(args) } } _J(" "HDR_HTTP" "FLD_ENDLN)
		_J(HDR_HOST" www.")_J(host)_J(FLD_FINISH) 
		ret = 1;
	}
	
cleanup:
#undef _J
#undef FLD_FINISH
#undef FLD_ENDLN
#undef SET_FIRST_CUT
	
if (host) free(host);
if (path) free(path);
if (cut) free(cut);

	return ret;
}





