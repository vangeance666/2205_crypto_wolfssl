#ifndef requests_h
#define requests_h
/** WolfSSL's helper function to read server response */
static int ClientRead(WOLFSSL *ssl, char *reply, int replyLen, int mustRead,
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


/** Helper function to write Message with GET/POST into SSL object */
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
		printf("hehe\n");
		printf("SSL_write%s msg error %d, %s\n", str, err,
			wolfSSL_ERR_error_string(err, buffer));
	}
	return err;
}

#endif
