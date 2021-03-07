#ifndef requests_h
#define requests_h



typedef enum {
	WRITE_OK,
	WRITE_FAIL,
} write_ret_t;

typedef enum {
	READ_FAIL,
	READ_OK,
	READ_INCOMPLETE
} read_ret_t;

/** WolfSSL's helper function to read server response */
static int client_read(WOLFSSL *ssl, char *reply, 
	int replyLen, int exitWithRet, int *setFinish, int *endBlock, FILE *fPtr) {

	int ret, err;
	char buffer[WOLFSSL_MAX_ERROR_SZ];

	time_t start, end; time(&start);

	int foundIndex = -1;

	int count = 0;
	do {
		err = 0; /* reset error */
		ret = wolfSSL_read(ssl, reply, replyLen);
		err = wolfSSL_get_error(ssl, 0);

		if (ret <= 0) {				
			if (err != WOLFSSL_ERROR_WANT_READ) {
				printf("SSL_read reply error %d, %s\n", err,
					wolfSSL_ERR_error_string(err, buffer));
				if (!exitWithRet) // exitWith Ret is to indicate that once error just ret from function. 
					fprintf(stderr, "SSL_read failed");
				else
					break;
			}
		}
		if (err == WOLFSSL_ERROR_WANT_READ) {
			time(&end);
			if (difftime(start, end) > 5) {//MAX_NON_BLOCK_SEC
				printf("Nonblocking read timeout\n");
				ret = WOLFSSL_FATAL_ERROR; // so that wont append 0
				break;
			}
		}
		
	} while ((err == WOLFSSL_ERROR_WANT_READ));

	if (ret > 0) 
		reply[ret] = 0; 	
	
	//if (err == 0 && fPtr) { // Will only write if the pointer is not null
	//	//printf("Yes got file\n");
	//	if (reply) {
	//		printf("%s\n", reply);
	//		fprintf(fPtr, "%s", reply);
	//	}
	//}

	foundIndex = str_index("\r\n\r\n", reply, 1);
	if (foundIndex != -1) {
		*endBlock = 1;
		*setFinish = (reply[foundIndex -1] == '0'); // So outside will stop
		/*printf("setFinish: %d\n", (reply[foundIndex - 1] == '0'));*/

	}
	

	return err;
}


/** Helper function to write Message with GET/POST into SSL object */
static int client_write(WOLFSSL *ssl, const char *msg, int msgSz, const char *str) {
	int ret, err;
	char buffer[WOLFSSL_MAX_ERROR_SZ];

	do {
		err = 0; /* reset error */
		ret = wolfSSL_write(ssl, msg, msgSz);
		if (ret <= 0) {
			err = wolfSSL_get_error(ssl, 0);
		}
	} while (err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ);
	if (ret != msgSz) {
		printf("SSL_write%s msg error %d, %s\n", str, err,
			wolfSSL_ERR_error_string(err, buffer));
	}
	return err;
}

#endif
