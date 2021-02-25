#ifndef callbacks_h
#define callbacks_h

static int myVerifyAction = VERIFY_OVERRIDE_ERROR;

static int myVerify(int preverify, WOLFSSL_X509_STORE_CTX *store)
{

	//If come here and preverify is 1, means local CA cert already successfully verified.
	// else do own processing. 
	char buffer[WOLFSSL_MAX_ERROR_SZ];

	WOLFSSL_X509* peer;
	(void)preverify;

	WOLFSSL_BIO *bio = NULL;
	WOLFSSL_STACK *sk = NULL;
	X509 *x509 = NULL;
	int i = 0;

	/* Verify Callback Arguments:
	* preverify:           1=Verify Okay, 0=Failure
	* store->error:        Failure error code (0 indicates no failure)
	* store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
	* store->error_depth:  Current Index
	* store->domain:       Subject CN as string (null term)
	* store->totalCerts:   Number of certs presented by peer
	* store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
	* store->store:        WOLFSSL_X509_STORE with CA cert chain
	* store->store->cm:    WOLFSSL_CERT_MANAGER
	* store->ex_data:      The WOLFSSL object pointer
	* store->discardSessionCerts: When set to non-zero value session certs
	will be discarded (only with SESSION_CERTS)
	*/

	printf("Preveryify: %d\n", preverify);

	printf("In verification callback, error = %d, %s\n", store->error,
		wolfSSL_ERR_error_string(store->error, buffer));

	peer = store->current_cert;
	if (peer) {
		char* issuer = wolfSSL_X509_NAME_oneline(
			wolfSSL_X509_get_issuer_name(peer), 0, 0);
		char* subject = wolfSSL_X509_NAME_oneline(
			wolfSSL_X509_get_subject_name(peer), 0, 0);
		printf("\tPeer's cert info:\n issuer : %s\n subject: %s\n", issuer,
			subject);

		bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
		if (bio != NULL) {
			wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE);
			wolfSSL_X509_print(bio, peer);
			wolfSSL_BIO_free(bio);
		}

		printf("---------------------------------\n");
		XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
		XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);



		/* retrieve x509 certs and display them on stdout */
		sk = wolfSSL_X509_STORE_GetCerts(store);

		for (i = 0; i < wolfSSL_sk_X509_num(sk); i++) {
			printf("I value: %d\n", i);
			x509 = wolfSSL_sk_X509_value(sk, i);
			bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
			if (bio != NULL) {
				wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE);
				wolfSSL_X509_print(bio, x509);
				wolfSSL_BIO_free(bio);
			}
		}
		wolfSSL_sk_X509_free(sk);


	}
	else
		printf("\tPeer has no cert!\n");

	printf("\tPeer certs: %d\n", store->totalCerts);

	printf("\tSubject's domain name at %d is %s\n", store->error_depth, store->domain);

	/* Testing forced fail case by return zero */
	if (myVerifyAction == VERIFY_FORCE_FAIL) {
		return 0; /* test failure case */
	}

	if (myVerifyAction == VERIFY_OVERRIDE_DATE_ERR &&
		(store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E)) {
		printf("Overriding cert date error as example for bad clock testing\n");
		return 1;
	}

	/* If error indicate we are overriding it for testing purposes */
	if (store->error != 0 && myVerifyAction == VERIFY_OVERRIDE_ERROR) {
		printf("\tAllowing failed certificate check, testing only "
			"(shouldn't do this in production)\n");
	}

	return 0;

	/* A non-zero return code indicates failure override */
	return (myVerifyAction == VERIFY_OVERRIDE_ERROR) ? 1 : preverify;
}

static void CRL_CallBack(const char *url)
{
	printf("CRL callback url = %s\n", url);
}


#endif
