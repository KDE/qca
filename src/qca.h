#ifndef QCA_H
#define QCA_H

#include<qstring.h>
#include<qcstring.h>

class QCA_SHA1Functions;

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
		Hash();
		virtual ~Hash();

		virtual void clear()=0;
		virtual void update(const QByteArray &a)=0;
		virtual QByteArray final()=0;
	};

	template <class T>
	class HashStatic
	{
	public:
		HashStatic<T>() {}

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
			return arrayToHex(hash(cs));
		}
	};

	class Cipher
	{
	public:
		Cipher();
		virtual ~Cipher();

		QByteArray key() const;
		QByteArray iv() const;
		void setKey(const QByteArray &a);
		void setIV(const QByteArray &a);

		virtual bool encrypt(const QByteArray &in, QByteArray *out, bool pad=true)=0;
		virtual bool decrypt(const QByteArray &in, QByteArray *out, bool pad=true)=0;

	private:
		QByteArray v_key, v_iv;
	};

	class SHA1 : public Hash, public HashStatic<SHA1>
	{
	public:
		SHA1();
		~SHA1();

		void clear();
		void update(const QByteArray &a);
		QByteArray final();

	private:
		struct QCA_SHA1Functions *f;
		int ctx;
	};

	/*class SHA256 : public Hash, public HashStatic<SHA256>
	{
	public:
		SHA256();
		~SHA256();

		void clear();
		void update(const QByteArray &a);
		QByteArray final();
	};

	class MD5 : public Hash, public HashStatic<MD5>
	{
	public:
		MD5();
		~MD5();

		void clear();
		void update(const QByteArray &a);
		QByteArray final();
	};

	class TripleDES : public Cipher
	{
	public:
		TripleDES();
		~TripleDES();

		bool encrypt(const QByteArray &in, QByteArray *out, bool pad=true);
		bool decrypt(const QByteArray &in, QByteArray *out, bool pad=true);
	};

	class AES128 : public Cipher
	{
	public:
		AES128();
		~AES128();

		bool encrypt(const QByteArray &in, QByteArray *out, bool pad=true);
		bool decrypt(const QByteArray &in, QByteArray *out, bool pad=true);
	};

	class AES256 : public Cipher
	{
	public:
		AES256();
		~AES256();

		bool encrypt(const QByteArray &in, QByteArray *out, bool pad=true);
		bool decrypt(const QByteArray &in, QByteArray *out, bool pad=true);
	};*/
};

#endif
