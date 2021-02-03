﻿#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <wolfssl/ssl.h>

#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/x509v3.h>

#define MAX_INPUT 10
#define MAX_NON_BLOCK_SEC   60

#define CERT_DET_LEN 2000
#define BUFF_SIZE 4096
#define IP_BUFF_SIZE 100

#define RESPONSE_SIZE 15001

//Youtube currently is ECC
//Xsite currently is RSA

#define HTTPS_PORT 443

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
#define YT_GET "GET / HTTP/1.1\r\nHost: youtube.com\r\n\r\n"
#define YT_POST "POST / HTTP/1.1\r\nHost: youtube.com\r\n\r\n"

//typedef enum {
//	SITE_YT = 1,
//	SITE_XSITE,
//	SITE_SLACK,
//	SITE_SKYPE
//} site_mode_t;

typedef enum {
	ENC_RSA = 1,
	ENC_ECC
} pub_key_alg_t;


static int cert_show_details(const pub_key_alg_t pubEncAlg,
	const char *certPath);
static int cert_manual_verify(WOLFSSL_CTX *ctx, const char *caCert,
	const char *vrfCert);

static int server_interact(WOLFSSL_CTX *ctx, const char *certPath, const char *certFldr,
	const char *sendMsg, const char *servHostName, const int portNo);

static int host_to_ip(const char *inName, char *outIp);

static int ClientRead(WOLFSSL *ssl, char *reply, int replyLen, int mustRead,
	const char* str, int exitWithRet);
static int ClientWrite(WOLFSSL *ssl, const char *msg, int msgSz, const char *str,
	int exitWithRet);

#define _IS(X) strcmp(input, X"\n") == 0
#define eprintf(M, G) {fprintf(stderr, "[Error][%s] %s ", __func__, M); goto G;}

void print_help() {
	printf("Please select the following choices: \n");
	//printf("-------- Viewing Website certifications --------");
	printf("1. View Youtube cert publickey info.\n");
	printf("2. View Reddit cert publickey info.\n");
	//printf("-------- Verification of CA Certs --------");
	printf("3. Youtube certs verification.\n");
	printf("4. Reddit cert verifications.\n");
	//printf("-------- Write GET request to sites --------");
	printf("5. Write Youtube GET.\n");
	printf("6. Write Reddit GET.\n");
	printf("7. Write Instagram GET.\n");
	printf("8. Write Slack GET.\n");
	//printf("-------- Write POST request to sites --------");
	printf("9. Write Youtube POST.\n");
	printf("10. Write Reddit POST.\n");
	printf("11. Write Instagram POST.\n");
	printf("12. Write Slack POST.\n");
}

int main(int argc, char** argv)
{
	int ret;
	char input[MAX_INPUT];

	WOLFSSL_CTX *ctx;
	WOLFSSL_X509 *cert;
	WOLFSSL *ssl;

	/* Start */
	if (ret = wolfSSL_Init() != WOLFSSL_SUCCESS)
		eprintf("Failed to init wolfSSL.\n", cleanup)

		// Create context 
	if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL)
		eprintf("Failed to create WolfSSL context.\n", ctx_cleanup)

	print_help();
	int end = 0;
	
	printf("\n\n");
	printf("Input ur choice: ");

	fgets(input, MAX_INPUT, stdin);

	if (_IS("1")) {	// 1. View Youtube cert publickey info.
		(void)cert_show_details(ENC_ECC, YT_CHAIN);
	}
	if (_IS("2"))	//2. View Reddit cert publickey info.
		cert_show_details(ENC_RSA, REDDIT_ROOT);
	if (_IS("3"))	//3. Youtube certs verification.
		if ((ret = cert_manual_verify(ctx, YT_ROOT, YT_MID))) fprintf(stdout, "Success %d\n", ret);
	if (_IS("4"))	//4. Reddit cert verifications.
		if ((ret = cert_manual_verify(ctx, REDDIT_MID, REDDIT_SERV))) fprintf(stdout, "Success %d\n", ret);
	if (_IS("5"))	//5. Write Youtube GET.
		if ((ret = server_interact(ctx, YT_ROOT, 0, YT_GET, YT_HOST, HTTPS_PORT))) fprintf(stdout, "Finished %d\n", ret);
	if (_IS("6"))	//6. Write Reddit GET.
		if ((ret = server_interact(ctx, 0, REDDIT_FLDR, REDDIT_GET, REDDIT_HOST, HTTPS_PORT))) fprintf(stdout, "Finished %d\n", ret);
	if (_IS("7"))	//7. Write Instagram GET.
		(void)server_interact(ctx, INSTA_CHAIN, 0, INSTA_GET, INSTA_HOST, HTTPS_PORT);
	if (_IS("8"))	//8. Write Slack GET.
		(void)server_interact(ctx, SLACK_ROOT, 0, SLACK_GET, SLACK_HOST, HTTPS_PORT);
	if (_IS("9"))	//9. Write Youtube POST.
		if ((ret = server_interact(ctx, 0, YT_FLDR, YT_POST, YT_HOST, HTTPS_PORT))) fprintf(stdout, "Finished %d\n", ret);
	if (_IS("10"))//10. Write Reddit POST.
		if ((ret = server_interact(ctx, 0, REDDIT_FLDR, REDDIT_POST, REDDIT_HOST, HTTPS_PORT))) fprintf(stdout, "Finished %d\n", ret);
	if (_IS("11"))	//11. Write Instagram POST.
		(void)server_interact(ctx, INSTA_CHAIN, 0, INSTA_POST, INSTA_HOST, HTTPS_PORT);
	if (_IS("12"))	//12. Write Slack POST.*/
		(void)server_interact(ctx, SLACK_ROOT, 0, SLACK_POST, SLACK_HOST, HTTPS_PORT);
	printf("Invalid choice, please enter again.\n");

	/*
	if (!show_cert_details(cert, ENC_RSA))
	fprintf(stderr, "[Error] Cant print cert details .\n");
	*/

	//server_interact(ctx, 0, REDDIT_FLDR, REDDIT_GET, "reddit.com", HTTPS_PORT);

cleanup:

ctx_cleanup:
	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
finish:
	return ret;
}


static int cert_show_details(const pub_key_alg_t pubEncAlg,
	const char *certPath) {
#define GN_INF(T, V) \
	char V[CERT_DET_LEN]; \
	nameSz = wolfSSL_X509_NAME_get_text_by_NID(name, T, \
	V, sizeof(V)); \
	printf(#V " = %s\n", V);
	int ret, nameSz, suc; size_t i;

	WOLFSSL_X509 *cert;
	WOLFSSL_EVP_PKEY *pubKeyTmp;

	RsaKey pubKeyRsa;
	ecc_key *pubKeyEcc;

	WOLFSSL_X509_NAME *name; word32 idx;

	// 1 Load cert from file
	if ((cert = wolfSSL_X509_load_certificate_file(certPath, SSL_FILETYPE_PEM)) == NULL)
		eprintf("Unable to load cert file to memory.\n", finish)

	// Retrieve public key from cert first
	if ((pubKeyTmp = wolfSSL_X509_get_pubkey(cert)) == NULL)
		eprintf("Failed to retrieve public key.\n", pu_key_cleanup)

	// Decode accordingly
	switch (pubEncAlg) {
		case ENC_RSA:
			wc_InitRsaKey(&pubKeyRsa, NULL);
			ret = wc_RsaPublicKeyDecode((byte*)pubKeyTmp->pkey.ptr, &idx,
				&pubKeyRsa, pubKeyTmp->pkey_sz);
			break;
		case ENC_ECC:
			wc_ecc_init(&pubKeyEcc);
			ret = wc_EccPublicKeyDecode((byte*)pubKeyTmp->pkey.ptr,
				&idx, &pubKeyEcc, pubKeyTmp->pkey_sz);
			break;
		default:
			eprintf("Invalid pub key encryption type.\n", ecc_key_cleanup)
	}

	if (ret != 0)
		eprintf("Failed to decode public key.\n", clean_all)

	if ((name = wolfSSL_X509_get_subject_name(cert)) == NULL)
		eprintf("Failed to extract subjectName info.\n", clean_all)

	GN_INF(ASN_COMMON_NAME, commonName)
	GN_INF(ASN_COUNTRY_NAME, countryName)
	GN_INF(ASN_LOCALITY_NAME, localityName)
	GN_INF(ASN_STATE_NAME, stateName)
	GN_INF(ASN_ORG_NAME, orgName)
	GN_INF(ASN_ORGUNIT_NAME, orgUnitName)

	printf("\n\n");

	printf("---Whole Public key in Hex---\n\n");
	for (i = 0; i < pubKeyTmp->pkey_sz; ++i) {
		printf("%02X ", pubKeyTmp->pkey.ptr[i] & 0xFF);
	}

	// TODO: Put Modulus and Exponent details here if RSA Pub key

	suc = 1;

#undef GN_INF
clean_all:


ecc_key_cleanup :
	wc_ecc_free(&pubKeyEcc);
rsa_key_cleanup:
	wc_FreeRsaKey(&pubKeyRsa);
pu_key_cleanup:
	wolfSSL_EVP_PKEY_free(pubKeyTmp);
finish:
	printf("before retunring 0\n");
	return 0;
}


static int cert_manual_verify(WOLFSSL_CTX *ctx, const char *caCert,
	const char *vrfCert) {

	// Verify locations method of verification
	/*if ((ret = wolfSSL_CTX_load_verify_locations(ctx, chainCert, 0)) != SSL_SUCCESS) {
	fprintf(stderr, "[Error] Failed to load cert file.\n");
	goto finish;}
	*/
	int ret, suc;
	WOLFSSL_CERT_MANAGER *cm = NULL;

	if ((cm = wolfSSL_CertManagerNew()) == NULL) {
		printf("wolfSSL_CertManagerNew() failed\n");
		goto manager_cleanup;
	}

	if ((ret = wolfSSL_CertManagerLoadCA(cm, caCert, NULL)) != SSL_SUCCESS) {
		fprintf(stderr, "[Error] wolfSSL_CertManagerLoadCA() failed (%d): %s\n",
			ret, wolfSSL_ERR_reason_error_string(ret));
		goto manager_cleanup;
	}

	if ((ret = wolfSSL_CertManagerVerify(cm, vrfCert, SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
		fprintf(stderr, "[Error] wolfSSL_CertManagerVerify() failed (%d): %s\n",
			ret, wolfSSL_ERR_reason_error_string(ret));
		goto manager_cleanup;
	}

	suc = 1;

manager_cleanup:
	wolfSSL_CertManagerFree(cm);
finish:
	return suc;
}

static int server_interact(WOLFSSL_CTX *ctx, const char *certPath, const char *certFldr,
	const char *sendMsg, const char *servHostName, const int portNo) {

	printf("%s \n", sendMsg);

	struct sockaddr_in servAddr;
	SOCKET_T sockfd; WOLFSSL *ssl;

	char servResponse[BUFF_SIZE], servIp[IP_BUFF_SIZE];
	int ret, suc, err; size_t i;

	// try get ip address from given hostname first as needed to config socket
	if (!host_to_ip(servHostName, servIp))
		eprintf("Unable to convert hostname to IP Address.\n", finish)
	else
		printf("Converted Hostname to IP Address: %s .\n", servIp);

	// Proceed with setting up socket details
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servAddr, 0, sizeof(servAddr));

	// Configure server details
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(portNo);
	servAddr.sin_addr.s_addr = inet_addr(servIp);

	if (connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)) == -1)
		eprintf("Failed to connect to socket\n", socket_cleanup)

		//tcp_connect(&sockfd, host, port, dtlsUDP, dtlsSCTP, ssl);

		// Load and verify the certs 
		if ((ret = wolfSSL_CTX_load_verify_locations(ctx, certPath, certFldr)) != SSL_SUCCESS)
			eprintf("Failed to load cert file.\n", finish);

	if ((ssl = wolfSSL_new(ctx)) == NULL)
		eprintf("Failed to load SSL struct.\n", ssl_cleanup)

	if (wolfSSL_set_fd(ssl, sockfd) != SSL_SUCCESS)
		eprintf("Failed to attach wolfssl to socket.\n", ssl_cleanup)

	if (wolfSSL_check_domain_name(ssl, servHostName) == WOLFSSL_SUCCESS)
		printf("SSl Domain Check Pass.\n\n");
	else
		eprintf("Failed cert domain check.\n", ssl_cleanup)

	if ((ret = wolfSSL_connect_cert(ssl)) != WOLFSSL_SUCCESS) {
		err = wolfSSL_get_error(ssl, 0);
		printf("WOLFSSL Connect Error No: %d\n", err);
		if (err == -188)
			printf("[Error] ASN sig error, no CA signer to verify certificate.\n");
		eprintf("Failed wolfSSL_connect().\n", ssl_cleanup)
	}

	(void)ClientWrite(ssl, sendMsg, strlen(sendMsg), "", 1);
	for (i = 1; i; i = ClientRead(ssl, servResponse, sizeof(servResponse) - 1, 1, "", 1));

	printf("===%s Respond===\n %s\n", servHostName, servResponse);

	suc = 1;

	//ssl = wolfSSL_new(ctx);
ssl_cleanup:
	wolfSSL_free(ssl);
socket_cleanup:
	close(sockfd);
finish:
	return suc;
}

static int host_to_ip(const char *inName, char *outIp) {

	WSADATA wsaData;
	struct hostent *remoteHost;
	struct in_addr **addrList;

	int suc, res;  size_t i;

	// For Windows need to use WSAStartup first
	if ((res = WSAStartup(MAKEWORD(2, 2), &wsaData)) != NULL) {
		fprintf(stderr, "[Error] WSASTARTUP Failed: %d\n", res);
		goto finish;
	}

	if ((remoteHost = gethostbyname(inName)) == NULL) {
		fprintf(stderr, "[Error] Unabe to gethostname.\n", res);
		goto finish;
	}

	addrList = (struct in_addr **)remoteHost->h_addr_list;
	for (i = 0; addrList[i] != 0; ++i) {
		strcpy(outIp, inet_ntoa(*addrList[i]));
		suc = 1;
		break;
	}

finish:
	return suc;
}


// WolfSSL's helper function to read server response
static int ClientRead(WOLFSSL* ssl, char* reply, int replyLen, int mustRead,
	const char* str, int exitWithRet) {

	int ret, err;
	char buffer[WOLFSSL_MAX_ERROR_SZ];

	time_t start, end; time(&start);

	do {
		err = 0; /* reset error */
		ret = wolfSSL_read(ssl, reply, replyLen);
		if (ret <= 0) {
			err = wolfSSL_get_error(ssl, 0);
#ifdef WOLFSSL_ASYNC_CRYPT
			if (err == WC_PENDING_E) {
				ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
				if (ret < 0) break;
			}
			else
#endif
				if (err != WOLFSSL_ERROR_WANT_READ) {
					printf("SSL_read reply error %d, %s\n", err,
						wolfSSL_ERR_error_string(err, buffer));
					if (!exitWithRet)
						fprintf(stderr, "SSL_read failed");
					else
						break;
				}
		}

		if (mustRead && err == WOLFSSL_ERROR_WANT_READ) {
			time(&end);
			if (difftime(start, end) > MAX_NON_BLOCK_SEC) {
				printf("Nonblocking read timeout\n");
				ret = WOLFSSL_FATAL_ERROR;
				break;
			}
		}
	} while ((mustRead && err == WOLFSSL_ERROR_WANT_READ)
#ifdef WOLFSSL_ASYNC_CRYPT
		|| err == WC_PENDING_E
#endif
		);
	if (ret > 0) {
		reply[ret] = 0; /* null terminate */
		printf("%s%s\n", str, reply);
	}

	return err;
}
//
// Helper function to write Message with GET/POST into SSL object
static int ClientWrite(WOLFSSL *ssl, const char *msg, int msgSz, const char *str)
{
	printf("Inside ClientWrite\n");

	int ret, err;
	char buffer[WOLFSSL_MAX_ERROR_SZ];

	do {
		err = 0; /* reset error */
		ret = wolfSSL_write(ssl, msg, msgSz);
		if (ret <= 0) {
			err = wolfSSL_get_error(ssl, 0);
#ifdef WOLFSSL_ASYNC_CRYPT
			if (err == WC_PENDING_E) {
				ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
				if (ret < 0) break;
			}
#endif
		}
	} while (err == WOLFSSL_ERROR_WANT_WRITE ||
		err == WOLFSSL_ERROR_WANT_READ
#ifdef WOLFSSL_ASYNC_CRYPT
		|| err == WC_PENDING_E
#endif
		);
	if (ret != msgSz) {
		printf("SSL_write%s msg error %d, %s\n", str, err,
			wolfSSL_ERR_error_string(err, buffer));
	}
	return err;
}