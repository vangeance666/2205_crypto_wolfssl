#ifndef certfields_h
#define certfields_h

/**
 * Prints certificate details of peer's
 * cert. 
 * 
 * @param ssl SSL Session object
 */
static void print_peer_details(WOLFSSL *ssl) {
	WOLFSSL_X509 *cert;
	cert = wolfSSL_get_peer_certificate(ssl);
	(void)print_cert_details(cert);
	wolfSSL_FreeX509(cert);
}

/**
 * Display cert's public key in Hex.
 * 
 * @param cert WolfSSL Cert object
 */
static void show_pkey_details(WOLFSSL_X509 *cert) {

	size_t i; WOLFSSL_EVP_PKEY *pubKeyTmp;

	pubKeyTmp = wolfSSL_X509_get_pubkey(cert);
	if (pubKeyTmp == NULL) {
		eprintf("Failed to retrieve public key.\n", finish)
	}	
	printf("PUBLIC KEY HEX:\n");
	for (i = 0; i < pubKeyTmp->pkey_sz; ++i) {
		printf("%02X ", pubKeyTmp->pkey.ptr[i] & 0xFF);
	} printf("\n");
	
finish:
	wolfSSL_EVP_PKEY_free(pubKeyTmp);
}


/**
 * Utilizes wolfSSL library to print 
 * all cert info. 
 * 
 * @param cert WolfSSL Cert object
 */
static void show_x509_bio_info(WOLFSSL_X509 *cert) {
	WOLFSSL_BIO *bio = NULL;
	bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
	if (bio != NULL) {
		wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE);
		wolfSSL_X509_print(bio, cert);
		wolfSSL_BIO_free(bio);
	}
}


/**
 * Manual Function of displaying cert's
 * public key details. Only prints 
 * Modulus and Exponent value of the
 * RSA Public key.
 *  
 * @param  x509 WolfSSL Cert object
 * @return      If successfull without errors 1, else 0
 */
static int show_x509_pub_key_info(WOLFSSL_X509 *x509) {
	
	char buffer[100];

	/* For RSA Key */
	RsaKey rsa;
	word32 idx = 0;
	int  sz, ret = 0, rawLen;
	byte lbit = 0;
	unsigned char *rawKey;
	/* -----------*/

	switch (x509->pubKeyOID) {
		case (RSAk):
			if (wc_InitRsaKey(&rsa, NULL) != 0) {
				eprintf("wc_InitRsaKey failure", finish);
			}
			if (wc_RsaPublicKeyDecode(x509->pubKey.buffer,
				&idx, &rsa, x509->pubKey.length) != 0) {
				wc_FreeRsaKey(&rsa);
				eprintf("Error decoding RSA key", finish);			
			}
			if ((sz = wc_RsaEncryptSize(&rsa)) < 0) {
				wc_FreeRsaKey(&rsa);
				eprintf("Error getting RSA key size", finish);
			}

			/* print out modulus */
			XSNPRINTF(buffer, sizeof(buffer) - 1, "-----------------Modulus-----------------\n");
			buffer[sizeof(buffer) - 1] = '\0';

			// Leading bits append to buffer leading bits
			if (mp_leading_bit(&rsa.n)) { 
				lbit = 1;
				XSTRNCAT(buffer, "00", 3);
			}

			rawLen = mp_unsigned_bin_size(&rsa.n);
			rawKey = (unsigned char*)XMALLOC(rawLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);


			if (!rawKey) {
				wc_FreeRsaKey(&rsa);
				eprintf("Memory error", finish);
			}

			mp_to_unsigned_bin(&rsa.n, rawKey);

			for (idx = 0; idx < (word32)rawLen; ++idx) {
				char val[5];
				int valSz = 5;
				if ((idx == 0) && !lbit) {
					XSNPRINTF(val, valSz - 1, "%02x", rawKey[idx]);
				} else if ((idx != 0) && (((idx + lbit) % 15) == 0)) {
					buffer[sizeof(buffer) - 1] = '\0';
					fprintf(stdout, "%s", buffer); // Print current line
					XSNPRINTF(buffer, sizeof(buffer) - 1,":\n");// Make next line
					XSNPRINTF(val, valSz - 1, "%02x", rawKey[idx]);
					
				} else {
					XSNPRINTF(val, valSz - 1, ":%02x", rawKey[idx]);
				}
				XSTRNCAT(buffer, val, valSz);
			} 
			XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);

			/* print out remaining modulus values */
			if ((idx > 0) && (((idx - 1 + lbit) % 15) != 0)) {
				buffer[sizeof(buffer) - 1] = '\0';
			}
			fprintf(stdout, "%s", buffer);

			/* ------ Exponent ------ */
			rawLen = mp_unsigned_bin_size(&rsa.e);
			if (rawLen < 0) {
				wc_FreeRsaKey(&rsa);
				eprintf("Error getting exponent size", finish);
			}

			if ((word32)rawLen < sizeof(word32)) {
				rawLen = sizeof(word32);
			}
			rawKey = (unsigned char*)XMALLOC(rawLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			if (!rawKey) {
				wc_FreeRsaKey(&rsa);
				eprintf("Memory error", finish);
			}

			// Print Exponent of RSA pub key
			XMEMSET(rawKey, 0, rawLen);
			mp_to_unsigned_bin(&rsa.e, rawKey);
			if ((word32)rawLen <= sizeof(word32)) {
				idx = *(word32*)rawKey;
			}
			XSNPRINTF(buffer, sizeof(buffer) - 1,"\nExponent: %d (0x%x)\n", idx, idx);
			printf("%s\n", buffer);
			/*------ End of Exponent ------*/

			XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			wc_FreeRsaKey(&rsa);

			break;
		
			
			
	}
	ret = 1;
finish:
	return ret;
}

/**
 * Prints all the x509 NAME fields of given
 * cert. 
 *  
 * @param cert WolfSSL Cert object
 */
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

/**
 * Prints cert's Issuer and Subject and all alt names.
 * 
 * @param cert WolfSSL Cert object
 */
static void show_x509_info(WOLFSSL_X509 *cert) {
	
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
