
#include "Cert.h"

#include "openssl/bio.h" 
#include "openssl/ssl.h" 
#include "openssl/err.h" 
#include "openssl/ossl_typ.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"



int x509Signer(CONF * req_cnf, X509 * x509, X509_REQ * req, EVP_PKEY *pKey,
		const char * ext, ASN1_INTEGER * serial, int days, const EVP_MD *  digest)
{

	EVP_PKEY * tmpKey = 0;

	X509V3_CTX ext_ctx;

	if (ext && !X509_set_version(x509, 2)) return -1;

	if (serial)

	{

		if (!X509_set_serialNumber(x509, serial)) return -1;

	}

	else

	{

		if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), 0L)) return -1;

	}

	if (!X509_set_issuer_name(x509, X509_REQ_get_subject_name(req))) return -1;

	if (!X509_gmtime_adj(X509_get_notBefore(x509), 0)) return -1;

	if (!X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * days)) return -1;

	if (!X509_set_subject_name(x509, X509_REQ_get_subject_name(req))) return -1;

	tmpKey = X509_REQ_get_pubkey(req);

	if (!tmpKey || !X509_set_pubkey(x509, tmpKey)) return -1;

	EVP_PKEY_free(tmpKey);

	X509V3_set_ctx(&ext_ctx, x509, x509, NULL, NULL, 0);

	X509V3_set_nconf(&ext_ctx, req_cnf);

	if (ext &&

		!X509V3_EXT_add_nconf(req_cnf, &ext_ctx, (char*)ext, x509))

	{

		return -1;

	}

	if (!X509_sign(x509, pKey, digest))

	{

		return -1;

	}

	return 0;

}




void x509Creator(string commonName,string countryName,string provinceName,string localityName,string orgName,string orgUnitName,
	string dstcertfn,long serialNO)
{

	X509_REQ  *req;
	int ret, len, mdlen, bits = 1024;
	long   version = 1;
	X509_NAME  *name;
	EVP_PKEY   *pkey;
	RSA        *rsa;
	X509_NAME_ENTRY *entry = NULL;
	char   bytes[100], mdout[20];
	unsigned long e = RSA_3;
	unsigned char *der, *p;
	FILE   *fp;
	const EVP_MD *md;
	X509   *x509;
	BIO    *b;
	STACK_OF(X509_EXTENSION) *exts;

	req = X509_REQ_new();
	ret = X509_REQ_set_version(req, version);
	name = X509_NAME_new();

	//C 国家代码 ST 州或省  L 城市  O机构 OU 部门  DM 域名
	strcpy(bytes, commonName.c_str());
	len = strlen(bytes);
	entry = X509_NAME_ENTRY_create_by_txt(&entry, "commonName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
	X509_NAME_add_entry(name, entry, 0, -1);

	strcpy(bytes, countryName.c_str());
	len = strlen(bytes);
	entry = X509_NAME_ENTRY_create_by_txt(&entry, "countryName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
	X509_NAME_add_entry(name, entry, 1, -1);

	strcpy(bytes, provinceName.c_str());
	len = strlen(bytes);
	entry = X509_NAME_ENTRY_create_by_txt(&entry, "stateOrProvinceName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
	X509_NAME_add_entry(name, entry, 1, -1);

	strcpy(bytes, localityName.c_str());
	len = strlen(bytes);
	entry = X509_NAME_ENTRY_create_by_txt(&entry, "localityName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
	X509_NAME_add_entry(name, entry, 1, -1);

	strcpy(bytes, orgName.c_str());
	len = strlen(bytes);
	entry = X509_NAME_ENTRY_create_by_txt(&entry, "organizationName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
	X509_NAME_add_entry(name, entry, 2, -1);

	strcpy(bytes, orgUnitName.c_str());
	len = strlen(bytes);
	entry = X509_NAME_ENTRY_create_by_txt(&entry, "organizationalUnitName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
	X509_NAME_add_entry(name, entry, 3, -1);

	/* subject name */
	ret = X509_REQ_set_subject_name(req, name);
	/* pub key */
	pkey = EVP_PKEY_new();
	rsa = RSA_generate_key(bits, e, NULL, NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);
	ret = X509_REQ_set_pubkey(req, pkey);


	/* attribute */
// 	strcpy(bytes, "test");
// 	len = strlen(bytes);
// 	ret = X509_REQ_add1_attr_by_txt(req, "organizationName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);
// 	strcpy(bytes, "ttt");
// 	len = strlen(bytes);
// 	ret = X509_REQ_add1_attr_by_txt(req, "organizationalUnitName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);

	string subjectAltName = string("DNS:") + commonName;
	strcpy(bytes, subjectAltName.c_str());
	len = strlen(bytes);
	ret = X509_REQ_add1_attr_by_txt(req, "subjectAltName", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);

	strcpy(bytes, "digitalSignature, nonRepudiation");
	len = strlen(bytes);
	ret = X509_REQ_add1_attr_by_txt(req, "keyUsage", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);

	strcpy(bytes, "serverAuth, clientAuth");
	len = strlen(bytes);
	ret = X509_REQ_add1_attr_by_txt(req, "extendedKeyUsage", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);

	strcpy(bytes, "Create by Gods");
	len = strlen(bytes);
	ret = X509_REQ_add1_attr_by_txt(req, "nsComment", V_ASN1_UTF8STRING, (unsigned char *)bytes, len);


	md = EVP_sha1();
	ret = X509_REQ_digest(req, md, (unsigned char *)mdout, (unsigned int *)&mdlen);
	ret = X509_REQ_sign(req, pkey, md);
	if (!ret) {
		printf("sign err!\n");
		X509_REQ_free(req);
		return;
	}

	string csrfilename = commonName + ".csr";
	/*  写入文件PEM 格式 */
	b = BIO_new_file(csrfilename.c_str(), "w");
	PEM_write_bio_X509_REQ(b, req);
	BIO_free(b);
	/* DER 编码 */
	len = i2d_X509_REQ(req, NULL);
	der = (unsigned char *)malloc(len);
	p = der;
	len = i2d_X509_REQ(req, &p);
	OpenSSL_add_all_algorithms();

	ret = X509_REQ_verify(req, pkey);
	if (ret < 0) {
		printf("verify err.\n");
	}
	fp = fopen(csrfilename.c_str(), "wb");
	fwrite(der, 1, len, fp);
	fclose(fp);

	//形成X509证书
	X509 *ptemp = X509_new();
	X509 *m_pClientCert;
	m_pClientCert = X509_new();
	X509 *m_pCACert = X509_new();  //证书签发者信息
	int days = 7300;
	long sn = serialNO;

	ret = X509_set_version(ptemp, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(ptemp), sn);
	X509_gmtime_adj(X509_get_notBefore(ptemp), 0);
	X509_gmtime_adj(X509_get_notAfter(ptemp), (long)60 * 60 * 24 * days);
	X509_set_subject_name(ptemp, X509_REQ_get_subject_name(req));
	X509_set_pubkey(ptemp, pkey);  //X509_PUBKEY_get(req->req_info->pubkey)
	X509_set_issuer_name(ptemp, X509_get_subject_name(ptemp));   //  证书签发者是自己

																 //设置扩展项目
	X509V3_CTX ctx;
	char myname[30] = "chenxiaopeng";
	char value[30] = "123456";
	X509V3_set_ctx(&ctx, m_pCACert, ptemp, NULL, NULL, 0);
	X509_EXTENSION *x509_ext = X509_EXTENSION_new();
	x509_ext = X509V3_EXT_conf(NULL, &ctx, myname, value);
	X509_add_ext(ptemp, x509_ext, -1);

	//设置签名值
	ret = X509_sign(ptemp, pkey, EVP_sha1());  //EVP_sha1()  EVP_sha256()
	if (ret == 0)
	{
		return;
	}

	//编码保存
	BIO *pbio;
	unsigned char *buf = NULL;
	pbio = BIO_new_file(dstcertfn.c_str(), "wb+");
	//	PEM_write_bio_X509(pbio,ptemp);
	//	i2d_X509_bio(pbio, ptemp);
	len = PEM_write_bio_X509(pbio, ptemp);    //PEM
	buf = (unsigned char *)malloc(len + 10);
	memset(buf, 0, len + 10);
	BIO_free(pbio);
	free(der);
	X509_REQ_free(req);
	X509_free(ptemp);
	X509_NAME_free(name);
	return;
}
