#ifndef QCA_H
#define QCA_H

#include<qstring.h>
#include<qcstring.h>

namespace QCA
{
	enum {
		CAP_SHA1      = 0x0001,
		CAP_MD5       = 0x0002,
		CAP_TripleDES = 0x0004,
		CAP_AES128    = 0x0008,
		CAP_AES256    = 0x0010,
		CAP_X509      = 0x0020,
		CAP_TLS       = 0x0040,
		CAP_SASL      = 0x0080,
		CAP_PGP       = 0x0100,
	};

	void init();
	bool isSupported(int capabilities);

	class SHA1
	{
	public:
		SHA1();
		~SHA1();

		void clear();
		void update(const QByteArray &);
		QByteArray final();

		static QByteArray hash(const QByteArray &);
		static QByteArray hash(const QCString &);
		static QString hashToString(const QByteArray &);
		static QString hashToString(const QCString &);
	}

	class MD5
	{
	public:
		MD5();
		~MD5();

		void clear();
		void update(const QByteArray &);
		QByteArray final();

		static QByteArray hash(const QByteArray &);
		static QByteArray hash(const QCString &);
		static QString hashToString(const QByteArray &);
		static QString hashToString(const QCString &);
	}
};

#endif
