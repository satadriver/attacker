

1 用到的命令和流程

// 生成顶级CA的公钥证书和私钥文件，有效期10年（RSA 1024bits，默认）

openssl req -new -x509 -days 7300 -keyout CARoot.key -out CARoot.crt 

// 为顶级CA的私钥文件去除保护口令

openssl rsa -in CARoot.key -out CARoot.key

 

// 生成顶级CA的公钥证书和私钥文件，有效期15年（RSA 2048bits，指定）

openssl req -newkey rsa:2048 -x509 -days 5480 -keyout CARoot.key -out CARoot.crt

// 为顶级CA的私钥文件去除保护口令

openssl rsa -in CARoot.key -out CARoot.key

 

// 为应用证书/中级证书生成私钥文件

openssl genrsa -out app.key 2048

// 根据私钥文件，为应用证书/中级证书生成 csr 文件（证书请求文件）

openssl req -new -key app.key -out app.csr

// 使用CA的公私钥文件给 csr 文件签名，生成应用证书，有效期5年

openssl ca -in app.csr -out app.crt -cert CARoot.crt -keyfile CARoot.key -days 1826 -policy policy_anything

// 使用CA的公私钥文件给 csr 文件签名，生成中级证书，有效期5年

openssl ca -extensions v3_ca -in app.csr -out app.crt -cert CARoot.crt -keyfile CARoot.key -days 1826 -policy policy_anything




2 subject字段:

openssl req -new -x509 -days 5480 -subj /C=US/ST=California/O=GeoAuth\ Inc./CN=Authentication\ Global\ Root -keyout CA.key -out CA.crt

设定的DN字段的值如果存在一些特殊字符【比如  （空格）、(（半角左括号）、)（半角右括号）……】，必须经过\（反斜杆）转义
要将值置为空的DN字段，您可以略去不写

//顶级CA在签发二者的时候，只是多少一个 -extensions v3_ca 选项的区别，这个选项赋予被签发的证书继续签发下级证书的权力。



3 签发策略
我们使用了选项-policy来指定签发策略为 policy_anything。如果没有使用此选项，则签发策略使用由配置文件 openssl.cnf 中相关条目指定的默认策略。
如果您没动过该配置文件的话，则默认策略为 policy_match。
此策略要求CA的公钥证书和应用证书请求文件中的Country Name、State or Province Name、Organization Name这三个字段必须 match 【也就是一样】。
如果您在应用证书请求文件中指定了和CA的公钥证书不一样的Country Name，且没有使用选项-policy，则会得到类似于下方的提示：
为什么openssl会使用这样的默认策略呢？其实很简单，openssl认定，仅当您建立组织内部的信任关系时，您才需要自己做CA。
既然是组织内部的信任关系，当然CA和应用证书就该有一样的所在国家、所在省份，以及所属组织

4 中级证书与应用证书的区别。
二者主要是在证书的扩展字段Subject Type的取值有所不同。中级证书该字段取值为"CA"，表明此证书依然可以作为CA，继续签发下级证书；
一般应用证书该字段的取值为"End Entity"，表明这已经是证书链的最后一个结点，自然也就不能继续签发下级证书。
若要生成中级证书（一般是出于信任关系建立的便利），则有以下方式：
上级CA在签署此证书时，加上 -extensions 选项，且选项参数设为 v3_ca （如步骤简记中所示）；
将 CA_default 条目中 x509_extensions 的值由 usr_cert改为 v3_ca；
将 usr_cert 条目中 basicConstraints的值由 CA:FALSE 改为 CA:true；




5 openssl配置文件的用法
(0) 
	nsCertType			= server
	nsComment			= "OpenSSL Generated Certificate"		
	keyUsage 			= nonRepudiation, digitalSignature, keyEncipherment
	issuerAltName		= email:move
	subjectAltName		= email:move

(1) 增加了democa文件夹和工作中的所有文件
(2) SAN
(3) 其他扩展
(4) 扩展其他字段及用法：
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


