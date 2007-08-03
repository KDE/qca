TEMPLATE = subdirs

SUBDIRS += \
	base64unittest \
	bigintunittest \
	certunittest \
	cipherunittest \
	clientplugin \
	cms \
	dsaunittest \
	filewatchunittest \
	hashunittest \
	hexunittest \
	kdfunittest \
	keybundle \
	keygenunittest \
	keylengthunittest \
	keystore \
	logger \
	macunittest \
	metatype \
	pgpunittest \
	pipeunittest \
	pkits \
	randomunittest \
	rsaunittest \
	securearrayunittest \
	staticunittest \
	symmetrickeyunittest \
	tls \
	velox

QMAKE_EXTRA_TARGETS += test
test.commands = sh ./checkall

