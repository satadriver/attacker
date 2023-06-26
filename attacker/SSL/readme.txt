

1 �õ������������

// ���ɶ���CA�Ĺ�Կ֤���˽Կ�ļ�����Ч��10�꣨RSA 1024bits��Ĭ�ϣ�

openssl req -new -x509 -days 7300 -keyout CARoot.key -out CARoot.crt 

// Ϊ����CA��˽Կ�ļ�ȥ����������

openssl rsa -in CARoot.key -out CARoot.key

 

// ���ɶ���CA�Ĺ�Կ֤���˽Կ�ļ�����Ч��15�꣨RSA 2048bits��ָ����

openssl req -newkey rsa:2048 -x509 -days 5480 -keyout CARoot.key -out CARoot.crt

// Ϊ����CA��˽Կ�ļ�ȥ����������

openssl rsa -in CARoot.key -out CARoot.key

 

// ΪӦ��֤��/�м�֤������˽Կ�ļ�

openssl genrsa -out app.key 2048

// ����˽Կ�ļ���ΪӦ��֤��/�м�֤������ csr �ļ���֤�������ļ���

openssl req -new -key app.key -out app.csr

// ʹ��CA�Ĺ�˽Կ�ļ��� csr �ļ�ǩ��������Ӧ��֤�飬��Ч��5��

openssl ca -in app.csr -out app.crt -cert CARoot.crt -keyfile CARoot.key -days 1826 -policy policy_anything

// ʹ��CA�Ĺ�˽Կ�ļ��� csr �ļ�ǩ���������м�֤�飬��Ч��5��

openssl ca -extensions v3_ca -in app.csr -out app.crt -cert CARoot.crt -keyfile CARoot.key -days 1826 -policy policy_anything




2 subject�ֶ�:

openssl req -new -x509 -days 5480 -subj /C=US/ST=California/O=GeoAuth\ Inc./CN=Authentication\ Global\ Root -keyout CA.key -out CA.crt

�趨��DN�ֶε�ֵ�������һЩ�����ַ�������  ���ո񣩡�(����������ţ���)����������ţ������������뾭��\����б�ˣ�ת��
Ҫ��ֵ��Ϊ�յ�DN�ֶΣ���������ȥ��д

//����CA��ǩ�����ߵ�ʱ��ֻ�Ƕ���һ�� -extensions v3_ca ѡ����������ѡ��豻ǩ����֤�����ǩ���¼�֤���Ȩ����



3 ǩ������
����ʹ����ѡ��-policy��ָ��ǩ������Ϊ policy_anything�����û��ʹ�ô�ѡ���ǩ������ʹ���������ļ� openssl.cnf �������Ŀָ����Ĭ�ϲ��ԡ�
�����û�����������ļ��Ļ�����Ĭ�ϲ���Ϊ policy_match��
�˲���Ҫ��CA�Ĺ�Կ֤���Ӧ��֤�������ļ��е�Country Name��State or Province Name��Organization Name�������ֶα��� match ��Ҳ����һ������
�������Ӧ��֤�������ļ���ָ���˺�CA�Ĺ�Կ֤�鲻һ����Country Name����û��ʹ��ѡ��-policy�����õ��������·�����ʾ��
Ϊʲôopenssl��ʹ��������Ĭ�ϲ����أ���ʵ�ܼ򵥣�openssl�϶���������������֯�ڲ������ι�ϵʱ��������Ҫ�Լ���CA��
��Ȼ����֯�ڲ������ι�ϵ����ȻCA��Ӧ��֤��͸���һ�������ڹ��ҡ�����ʡ�ݣ��Լ�������֯

4 �м�֤����Ӧ��֤�������
������Ҫ����֤�����չ�ֶ�Subject Type��ȡֵ������ͬ���м�֤����ֶ�ȡֵΪ"CA"��������֤����Ȼ������ΪCA������ǩ���¼�֤�飻
һ��Ӧ��֤����ֶε�ȡֵΪ"End Entity"���������Ѿ���֤���������һ����㣬��ȻҲ�Ͳ��ܼ���ǩ���¼�֤�顣
��Ҫ�����м�֤�飨һ���ǳ������ι�ϵ�����ı��������������·�ʽ��
�ϼ�CA��ǩ���֤��ʱ������ -extensions ѡ���ѡ�������Ϊ v3_ca ���粽��������ʾ����
�� CA_default ��Ŀ�� x509_extensions ��ֵ�� usr_cert��Ϊ v3_ca��
�� usr_cert ��Ŀ�� basicConstraints��ֵ�� CA:FALSE ��Ϊ CA:true��




5 openssl�����ļ����÷�
(0) 
	nsCertType			= server
	nsComment			= "OpenSSL Generated Certificate"		
	keyUsage 			= nonRepudiation, digitalSignature, keyEncipherment
	issuerAltName		= email:move
	subjectAltName		= email:move

(1) ������democa�ļ��к͹����е������ļ�
(2) SAN
(3) ������չ
(4) ��չ�����ֶμ��÷���
[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType   = server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment   = "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl  = http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always,issuer:always



[ proxy_cert_ext ]
# These extensions should be added when creating a proxy certificate

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType   = server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment   = "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl  = http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This really needs to be in place for it to be a proxy certificate.
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo


