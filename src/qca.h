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
		CAP_BlowFish  = 0x0008,
		CAP_TripleDES = 0x0010,
		CAP_AES128    = 0x0020,
		CAP_AES256    = 0x0040,
		CAP_RSA       = 0x0080,

		//CAP_X509      = 0x0040,
		//CAP_TLS       = 0x0080,
		//CAP_SASL      = 0x0100,
	};

	enum {
		CBC = 0x0001,
		CFB = 0x0002,
	};

	enum {
		Encrypt = 0x0001,
		Decrypt = 0x0002,
	};

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
		void reset(int dir, int mode, const QByteArray &key, const QByteArray &iv);
		bool update(const QByteArray &a);
		QByteArray final();

	protected:
		Cipher(QCA_CipherFunctions *, int dir, int mode, const QByteArray &key, const QByteArray &iv);

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
			return obj.dyn_generateIV();
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

	class BlowFish : public Cipher, public CipherStatic<BlowFish>
	{
	public:
		BlowFish(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray());
	};

	class TripleDES : public Cipher, public CipherStatic<TripleDES>
	{
	public:
		TripleDES(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray());
	};

	class AES128 : public Cipher, public CipherStatic<AES128>
	{
	public:
		AES128(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray());
	};

	class AES256 : public Cipher, public CipherStatic<AES256>
	{
	public:
		AES256(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray());
	};

	class RSA;
	class RSAKey
	{
	public:
		RSAKey();
		RSAKey(const RSAKey &from);
		RSAKey & operator=(const RSAKey &from);
		~RSAKey();

		bool isNull() const;

		QByteArray toDER() const;
		bool fromDER(const QByteArray &a, bool sec=false);

		// only call if you know what you are doing
		bool fromNative(void *);

	private:
		class Private;
		Private *d;

		friend class RSA;
		int internalContext() const;
		bool generate(unsigned int bits);
	};

	class RSA
	{
	public:
		RSA();
		~RSA();

		RSAKey key() const;
		void setKey(const RSAKey &);

		bool encrypt(const QByteArray &a, QByteArray *out) const;
		bool decrypt(const QByteArray &a, QByteArray *out) const;

		static RSAKey generateKey(unsigned int bits);

	private:
		RSAKey v_key;
	};
};

#endif
