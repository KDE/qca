#ifndef QCA_H
#define QCA_H

#include<qstring.h>
#include<qcstring.h>

#include<stdio.h>

namespace QCA
{
	enum {
		CAP_SHA1      = 0x0001,
		CAP_SHA256    = 0x0002,
		CAP_MD5       = 0x0004,
		CAP_TripleDES = 0x0008,
		CAP_AES128    = 0x0010,
		CAP_AES256    = 0x0020,
		CAP_X509      = 0x0040,
		CAP_TLS       = 0x0080,
		CAP_SASL      = 0x0100,
		CAP_PGP       = 0x0200,
	};

	void init();
	bool isSupported(int capabilities);

	QString arrayToHex(const QByteArray &);

	class Hash
	{
	public:
		Hash() {}
		virtual ~Hash() {}

		virtual void clear()=0;
		virtual void update(const QByteArray &)=0;
		virtual QByteArray final()=0;
	};

	template <class T> class HashStatic
	{
	public:
		static QByteArray hash(const QByteArray &a)
		{
			T obj;
			obj.update(a);
			return obj.final();
		}

		static QByteArray hash(const QCString &cs)
		{
			QByteArray a(cs.length());
			memcpy(a.data(), cs.data(), a.size());
			return hash(a);
		}

		static QString hashToString(const QByteArray &a)
		{
			return arrayToHex(hash(a));
		}

		static QString hashToString(const QCString &cs)
		{
			return arrayToHex(hash(a));
		}
	};

	class SHA1 : public Hash, public HashStatic<SHA1>
	{
	public:
		SHA1();
		~SHA1();

		void clear();
		void update(const QByteArray &);
		QByteArray final();
	};

	class MD5 : public Hash, public HashStatic<MD5>
	{
	public:
		MD5();
		~MD5();

		void clear();
		void update(const QByteArray &);
		QByteArray final();
	};
};

#endif
