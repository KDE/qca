#ifndef QCA_H
#define QCA_H

#include<qstring.h>
#include<qcstring.h>

struct QCA_HashFunctions;
struct QCA_CipherFunctions;

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

	enum { Encrypt, Decrypt };

	void init();
	bool isSupported(int capabilities);

	QString arrayToHex(const QByteArray &);
	QByteArray hexToArray(const QString &);

	class Hash
	{
	public:
		Hash(const Hash &);
		Hash & operator=(const Hash &);
		~Hash();

		void clear();
		void update(const QByteArray &a);
		QByteArray final();

	protected:
		Hash(QCA_HashFunctions *);

	private:
		class Private;
		Private *d;
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
		Cipher(const Cipher &);
		Cipher & operator=(const Cipher &);
		~Cipher();

		QByteArray dyn_generateKey() const;
		QByteArray dyn_generateIV() const;
		void reset(int dir, const QByteArray &key, const QByteArray &iv);
		void update(const QByteArray &a);
		QByteArray final();

	protected:
		Cipher(QCA_CipherFunctions *, int dir=Encrypt, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray());

	private:
		class Private;
		Private *d;
	};

	template <class T>
	class CipherStatic
	{
	public:
		CipherStatic<T>() {}

		static QByteArray generateKey()
		{
			T obj;
			return obj.dyn_generateKey();
		}

		static QByteArray generateIV()
		{
			T obj;
			return obj.dyn_generateKey();
		}
	};

	class SHA1 : public Hash, public HashStatic<SHA1>
	{
	public:
		SHA1();
	};

	class SHA256 : public Hash, public HashStatic<SHA256>
	{
	public:
		SHA256();
	};

	class MD5 : public Hash, public HashStatic<MD5>
	{
	public:
		MD5();
	};

	class TripleDES : public Cipher, public CipherStatic<TripleDES>
	{
	public:
		TripleDES(int dir=Encrypt, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray());
	};

	class AES128 : public Cipher, public CipherStatic<AES128>
	{
	public:
		AES128(int dir=Encrypt, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray());
	};

	class AES256 : public Cipher, public CipherStatic<AES128>
	{
	public:
		AES256(int dir=Encrypt, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray());
	};
};

#endif
