TEMPLATE = subdirs

SUBDIRS += \
	aes-cmac \
	base64test \
	certtest \
	ciphertest \
	cms \
        #cmssigner \   # commenting out for now, requires QtGui
	eventhandlerdemo \
	hashtest \
	hextest \
	keyloader \
	mactest \
	md5crypt \
	providertest \
	publickeyexample \
	randomtest \
	rsatest \
	sasltest \
	saslservtest \
	ssltest \
	sslservtest \
	tlssocket
