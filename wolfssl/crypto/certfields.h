#ifndef certfields_h
#define certfields_h

static void print_peer_details(WOLFSSL *ssl) {
	WOLFSSL_X509 *cert;
	cert = wolfSSL_get_peer_certificate(ssl);
	(void)print_cert_details(cert);
	wolfSSL_FreeX509(cert);
}

static void show_pkey_details(WOLFSSL_X509 *cert) {

	size_t i; WOLFSSL_EVP_PKEY *pubKeyTmp;

	pubKeyTmp = wolfSSL_X509_get_pubkey(cert);
	if (pubKeyTmp == NULL) {
		eprintf("Failed to retrieve public key.\n", finish)
	}

	printf("PUBLIC KEY:\n");
	for (i = 0; i < pubKeyTmp->pkey_sz; ++i) {
		printf("%02X", pubKeyTmp->pkey.ptr[i] & 0xFF);
	} printf("\n");
	
finish:
	wolfSSL_EVP_PKEY_free(pubKeyTmp);
}

static void show_x509_bio_info(WOLFSSL_X509 *cert) {
	WOLFSSL_BIO *bio = NULL;
	bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
	if (bio != NULL) {
		wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE);
		wolfSSL_X509_print(bio, cert);
		wolfSSL_BIO_free(bio);
	}
}

static void show_x509_name_info(WOLFSSL_X509 *cert) {

#define GN_INF(T, V) \
	char V[CERT_DET_LEN]; \
	nameSz = wolfSSL_X509_NAME_get_text_by_NID(name, T, \
	V, sizeof(V)); \
	printf(#V " = %s\n", V);

	WOLFSSL_X509_NAME *name;
	int ret, nameSz, sigType, suc; size_t i;

	if ((name = wolfSSL_X509_get_subject_name(cert)) == NULL) 
		eprintf("wolfSSL_X509_get_subject_name failed\n", finish);
	
	GN_INF(ASN_COMMON_NAME, commonName)
	GN_INF(ASN_COUNTRY_NAME, countryName)
	GN_INF(ASN_LOCALITY_NAME, localityName)
	GN_INF(ASN_STATE_NAME, stateName)
	GN_INF(ASN_ORG_NAME, orgName)
	GN_INF(ASN_ORGUNIT_NAME, orgUnit)

#undef GN_INF
finish:
	return;
}

static void show_x509_info(WOLFSSL_X509 *cert) {
	//For now only this 3 first.
	char *issuer, *subject, *altName;

	subject = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(cert), 0, 0);
	issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(cert), 0, 0);

	printf("%s: %s\n%s: %s\n", "Issuer:", issuer, "Subject:", subject);

	while ((altName = wolfSSL_X509_get_next_altname(cert)) != NULL)
		printf("%s = %s\n", "Altname", altName);

clean_all:
	XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
	XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);
}




#endif
