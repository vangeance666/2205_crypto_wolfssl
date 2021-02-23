#ifndef certfields_h
#define certfields_h

static pub_key_enc_t decode_pub_key(WOLFSSL_EVP_PKEY *pubKeyTmp) {

	pub_key_enc_t pubKeyEncType = ENC_NONE;
	RsaKey pubKeyRsa;
	ecc_key *pubKeyEcc;
	word32 idx;
	int ret;


	idx = 0;
	wc_ecc_init(&pubKeyEcc);
	ret = wc_EccPublicKeyDecode((byte*)pubKeyTmp->pkey.ptr,
		&idx, &pubKeyEcc, pubKeyTmp->pkey_sz);
	if (ret == 0) {
		printf("BBBB\n");
		return ENC_ECC;
	}

	idx = 0;
	wc_InitRsaKey(&pubKeyRsa, NULL);
	ret = wc_RsaPublicKeyDecode((byte*)pubKeyTmp->pkey.ptr, &idx,
		&pubKeyRsa, pubKeyTmp->pkey_sz);
	if (ret == 0) {
		printf("XXXX\n");
		return ENC_RSA;
	}

	

clean:
	printf("Cleaned\n");
//ecc_key_cleanup:
//	wc_ecc_free(&pubKeyEcc);
//rsa_key_cleanup:
//	wc_FreeRsaKey(&pubKeyRsa);
	return pubKeyEncType;
}

static void show_pkey_details(WOLFSSL_X509 *cert) {
	printf("show_pkey_details\n");

	size_t i;
	WOLFSSL_EVP_PKEY *pubKeyTmp;
	pubKeyTmp = wolfSSL_X509_get_pubkey(cert);
	if (pubKeyTmp == NULL) {
		eprintf("Failed to retrieve public key.\n", finish)
	}
	
	pub_key_enc_t temp = decode_pub_key(pubKeyTmp);

	/*RsaKey pubKeyRsa;
	ecc_key *pubKeyEcc;
	word32 idx;
	int ret;


	idx = 0;
	wc_ecc_init(&pubKeyEcc);
	ret = wc_EccPublicKeyDecode((byte*)pubKeyTmp->pkey.ptr,
		&idx, &pubKeyEcc, pubKeyTmp->pkey_sz);
	printf("PUBLIC KEY:\n");
	for (i = 0; i < pubKeyTmp->pkey_sz; ++i) {
		printf("%02X", pubKeyTmp->pkey.ptr[i] & 0xFF);
	} printf("\n");*/
	printf("PUBLIC KEY:\n");
	for (i = 0; i < pubKeyTmp->pkey_sz; ++i) {
		printf("%02X", pubKeyTmp->pkey.ptr[i] & 0xFF);
	} printf("\n");

	printf("Temp: %d\n", temp);
	if (temp != ENC_NONE) {
		printf("PUBLIC KEY:\n");
		for (i = 0; i < pubKeyTmp->pkey_sz; ++i) {
			printf("%02X", pubKeyTmp->pkey.ptr[i] & 0xFF);
		} printf("\n");
	}
finish:
	wolfSSL_EVP_PKEY_free(pubKeyTmp);
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
