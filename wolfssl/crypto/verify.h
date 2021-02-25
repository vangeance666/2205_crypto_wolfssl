#pragma once
#ifndef verify_h
#define verify_h


static int cert_manual_verify(const char *caCert,
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


#endif