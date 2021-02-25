#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

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

#define BUFFER_SIZE 10000

#define crlPemDir "../../certs/crl"

#define MOZILLA_ROOT "./certs/mozilla-roots-cas.pem"


typedef struct sockaddr_in  SOCKADDR_IN_T;



//

typedef enum {
	ADDR_DEFAULT,
	ADDR_SUCESS,
	ADDR_WSA_FAIL,
	ADDR_INVALID_ADDR_PTR,
	ADDR_INVALID_PEER_IP
} addr_ret_t;

typedef enum {
	TCP_DEFAULT,
	TCP_SUCESS,
	TCP_ADDR_FAIL,
	TCP_CONNECT_FAIL
}tcp_ret_t;

typedef enum {
	SES_DEFAULT,
	SES_SUCESS,
	SES_WOLF_INIT_FAIL,
	SES_CTX_FAIL,
	SES_SSL_FAIL,
	SES_CA_LOAD_FAIL,
	SES_SOCKET_FAIL,
	SES_FD_FAIL,
	SES_DOMAIN_CHECK_FAIL,
	SES_HANDSHAKE_FAIL
} ses_ret_t;

static char request[] = "";

int main(int argc, char** argv)
{

	int ret;
	char input[MAX_INPUT];
	const char* type = NULL;
	const char* url = NULL;
	const char* para = "";

	//checks if input exist, kind of 
	if (argc > 2) {
		type = argv[1]; //GET or POST
		url = argv[2]; //<url>/<path1>/<path2>
		para = argv[3]; //parameter=value
		printf("type = %s , url = %s , para = %s \n",type,url,para);
		//create request, scroll all the way down to see function
		char* createReq(char *type[], char *url[], char * para[]);
		createReq(type, url, para);
		printf(request);

		//query request?
		ret = start_session(request, url, HTTPS_PORT);
	}

	// Usage for seeing message across.
	ret = start_session(YT_GET, "youtube.com", HTTPS_PORT);

	//test_crl();
	//start_session("youtube.com", VERIFY_OVERRIDE_DATE_ERR);
	//cert_show_details(ENC_RSA, YT_ROOT);


	//print_help();
	//int end = 0;
	//
	//printf("\n\n");
	//printf("Input ur choice: ");

	//fgets(input, MAX_INPUT, stdin);

	/* Can modify program to be like arg parser but thats for later. */

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
 * @return          Session enum status code <ses_ret_t>
 */
static ses_ret_t new_session(WOLFSSL_CTX *ctx, const char *zmsg, 
	const char *hostname, word16 port, char *outMsg, int outMsgSz) {

	WOLFSSL *ssl; size_t i;

	tcp_ret_t tcpRet;
	ses_ret_t retCode = SES_DEFAULT;	

	SOCKET_T sockfd;
	
	
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
	
	// Store received buffer into buffer
	for (i = 1; i; i = ClientRead(ssl, outMsg, outMsgSz - 1, 1, "", 1));


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
static int start_session(const char *zmsg, const char *host, word16 port) {

	ses_ret_t retCode;

	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		retCode = SES_WOLF_INIT_FAIL; 
		eprintf("WolfSSL_Init failed", wolf_cleanup);
	}
			
	WOLFSSL_CTX		*ctx;

	
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
	//wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myVerify);

	char serverResponse[BUFFER_SIZE];

	/* Start of one session */
	retCode = new_session(ctx, zmsg, host, port, serverResponse, sizeof(serverResponse));
	/* End of one session */

	printf("serverResponse: \n%s\n", serverResponse);
	// Multiple rounds 
	

ctx_cleanup:
	wolfSSL_CTX_free(ctx);
wolf_cleanup:
	wolfSSL_Cleanup();
finish:
	return retCode;
}

char* getPath(char url[],char host[]) {
	//printf("URL is %s and HOST is %s\n", url, host);
	int i, j, ls, lw, temp, chk = 0;
	ls = strlen(url);
	lw = strlen(host);
	for (i = 0; i < ls; i++)
	{
		temp = i;
		for (j = 0; j < lw; j++)
		{
			if (url[i] == host[j])
				i++;
		}
		chk = i - temp;
		if (chk == lw)
		{
			i = temp;
			for (j = i; j < (ls - lw); j++)
				url[j] = url[j + lw];
			ls = ls - lw;
			url[j] = '\0';
		}
	}

//	printf("path is %s", url);
	return url;
}

char* createReq(char type[], char url[],char para[]) {
	char* path = "";
	char* host = "";
	char tempurl[] = "";
	memcpy(tempurl, url, strlen(url) + 1);

	//printf("TempURL is  %s\n", tempurl);
	host = strtok(url, "/");

	path = getPath(tempurl, host);

	//printf("Host is %s and path is %s\n", host , path);

	
	if (strcmp(type,"post") == 0) {
		//should see sth like 
		//post / http/1.1
		//Host: <url>

		//parameter=value
		printf("asd");
		char header[] = " HTTP/1.1\r\nHost: ";
		strcat(request, type);
		strcat(request, "/");
		strcat(request, path);
		strcat(request, " ");
		strcat(request, header);
		strcat(request, host);
		strcat(request, "\r\n\r\n");
		strcat(request, para);
		//return request;
	}
	else if (strcmp(type, "get") == 0) {
		//should see sth like 
		//Get /<webpage>?parameter=value http/1.1
		//Host: <url>
		printf("lol");
		char header[] = " HTTP/1.1\r\nHost: ";
		strcat(request, type);
		strcat(request, " /");
		strcat(request, path);
		strcat(request, "?");
		strcat(request, para);
		strcat(request, header);
		strcat(request, host);
		strcat(request, "\r\n\r\n");
		
		//return request;
	}

	
}
