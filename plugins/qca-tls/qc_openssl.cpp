/*
-----BEGIN QCMOD-----
name: openssl
arg: with-openssl-inc=[path],Path to OpenSSL include files
arg: with-openssl-lib=[path],Path to OpenSSL library files
-----END QCMOD-----
*/
class qc_openssl : public ConfObj
{
public:
	qc_openssl(Conf *c) : ConfObj(c) {}
	QString name() const { return "OpenSSL"; }
	QString shortname() const { return "openssl"; }
	bool exec()
	{
		QString inc, lib;
		QString s;

		s = conf->getenv("QC_WITH_OPENSSL_INC");
		if(!s.isEmpty()) {
			if(!conf->checkHeader(s, "openssl/ssl.h"))
				return false;
			inc = s;
		}
		else {
			QStringList extra;
			extra += "/usr/kerberos/include"; // Redhat 9?
			if(!conf->findHeader("/openssl/ssl.h", extra, &s))
				return false;
			inc = s;
		}

		s = conf->getenv("QC_WITH_OPENSSL_LIB");
		if(!s.isEmpty()) {
			if(!conf->checkLibrary(s, "ssl"))
				return false;
			lib = QString("-L") + s;
		}
		else {
			if(!conf->findLibrary("ssl", &s))
				return false;
			lib = s;
		}

		// is it at least openssl 0.9.7?
		QString str =
			"#include<openssl/opensslv.h>\n"
			"int main()\n"
			"{\n"
			"  unsigned long x = OPENSSL_VERSION_NUMBER;\n"
			"  if(x >= 0x00907000) return 0; else return 1;\n"
			"}\n";
		QString ext;
		if(!inc.isEmpty())
			ext += QString("-I") + inc + ' ';
		if(!lib.isEmpty())
			ext += QString("-L") + lib + " -lssl -lcrypto ";
		int ret;
		if(!conf->doCompileAndLink(str, ext, &ret))
			return false;
		if(ret == 0)
			conf->addDefine("OSSL_097");

		if(!inc.isEmpty())
			conf->addIncludePath(inc);
		if(!lib.isEmpty())
			conf->addLib(QString("-L") + s);
		conf->addLib("-lssl -lcrypto");

		return true;
	}
};
