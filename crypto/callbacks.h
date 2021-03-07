#ifndef callbacks_h
#define callbacks_h

static int myVerifyAction = VERIFY_OVERRIDE_DATE_ERR;

static int myVerify(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
	//If come here and preverify is 1, means local CA cert already successfully verified.

	WOLFSSL_X509 *peer;
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

	peer = store->current_cert;
	if (peer) {
		/* retrieve x509 certs and display them on stdout */
		sk = wolfSSL_X509_STORE_GetCerts(store);
		for (i = 0; i < wolfSSL_sk_X509_num(sk); i++) {
			x509 = wolfSSL_sk_X509_value(sk, i);
			show_x509_bio_info(x509);
		}
	}
	else
		printf("\tPeer has no cert!\n");
	/* A non-zero return code indicates failure override */
	return (myVerifyAction == VERIFY_OVERRIDE_ERROR) ? 1 : preverify;
}

static void CRL_CallBack(const char *url)
{
	printf("CRL callback url = %s\n", url);
}

#endif
