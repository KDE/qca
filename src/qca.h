/*
 * qca.h - Qt Cryptographic Architecture
 * Copyright (C) 2003,2004  Justin Karneges
 * Copyright (C) 2004  Brad Hards <bradh@frogmouth.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef QCA_H
#define QCA_H

#include <qstring.h>
#include <qcstring.h>
#include <qdatetime.h>
#include <qmap.h>
#include <qptrlist.h>
#include <qobject.h>
#include <qtextstream.h>

#ifdef Q_OS_WIN32
# ifndef QCA_STATIC
#  ifdef QCA_MAKEDLL
#   define QCA_EXPORT __declspec(dllexport)
#  else
#   define QCA_EXPORT __declspec(dllimport)
#  endif
# endif
#endif
#ifndef QCA_EXPORT
# define QCA_EXPORT
#endif

#ifdef Q_OS_WIN32
# ifdef QCA_PLUGIN_DLL
#  define QCA_PLUGIN_EXPORT extern "C" __declspec(dllexport)
# else
#  define QCA_PLUGIN_EXPORT extern "C" __declspec(dllimport)
# endif
#endif
#ifndef QCA_PLUGIN_EXPORT
# define QCA_PLUGIN_EXPORT extern "C"
#endif

class QHostAddress;
class QStringList;

class QCAProvider;
class QCA_HashContext;
class QCA_CipherContext;
class QCA_CertContext;

/**
 * Qt Cryptographic Architecture
 *
 * This library provides an easy API for the following features:
 *   - SSL/TLS
 *   - X509 certificate (Cert)
 *   - Simple Authentication and Security Layer (SASL)
 *   - RSA
 *   - Hashing 
 *       - SHA0
 *       - SHA1
 *       - MD2
 *       - MD4
 *       - MD5
 *       - RIPEMD160
 *   - Ciphers
 *       - BlowFish
 *       - TripleDES
 *       - AES (AES128, AES256)
 *
 * Functionality is supplied via plugins.  This is useful for avoiding
 * dependence on a particular crypto library and makes upgrading easier,
 * as there is no need to recompile your application when adding or
 * upgrading a crypto plugin.  Also, by pushing crypto functionality into
 * plugins, your application is free of legal issues, such as export
 * regulation.
 *
 * And of course, you get a very simple crypto API for Qt, where you can
 * do things like:
 * \code
 * QString hash = QCA::SHA1::hashToString(blockOfData);
 * \endcode
 */

// Direct secure memory access.  For interfacing with C libraries if needed.
QCA_EXPORT void *qca_secure_alloc(int bytes);
QCA_EXPORT void qca_secure_free(void *p);

QCA_EXPORT class QSecureArray
{
public:
	QSecureArray();
	QSecureArray(int size);
	QSecureArray(const QByteArray &a);
	QSecureArray(const QSecureArray &from);
	~QSecureArray();

	QSecureArray & operator=(const QSecureArray &from);
	QSecureArray & operator=(const QByteArray &a);
	char & operator[](int index);
	const char & operator[](int index) const;

	char *data() const;
	const char & at(uint index) const;
	char & at(uint index);
	uint size() const;
	bool isEmpty() const;
	bool resize(uint size);

	QSecureArray copy() const;
	void detach();
	QByteArray toByteArray() const;

private:
	class Private;
	Private *d;

	void reset();
};

/**
 * Arbitrary precision integer
 *
 * %QBigInteger provides arbitrary precision integers.
 * \code
 * if ( QBigInteger("3499543804349") == 
 *      QBigInteger("38493290803248") + QBigInteger( 343 ) )
 * {
 *       // do something
 * }
 * \endcode
 *       
 **/
QCA_EXPORT class QBigInteger
{
public:
	/**
	 * Constructor. Creates a new QBigInteger, initialised to zero.
	 */
	QBigInteger();

	/**
	 * \overload
	 *
	 * \param n an alternative integer initialisation value.
	 */
	QBigInteger(int n);

	/**
	 * \overload
	 *
	 * \param s an alternative initialisation value, encoded as a string
	 *
	 * \code
	 * QBigInteger b ( "9890343" );
	 * \endcode
	 */
	QBigInteger(const QString &s);

	/**
	 * \overload
	 *
	 * \param a an alternative initialisation value, encoded as QSecureArray
	 */
	QBigInteger(const QSecureArray &a);

	/**
	 * \overload
	 *
	 * \param from an alternative initialisation value, encoded as a %QBigInteger
	 */
	QBigInteger(const QBigInteger &from);

	~QBigInteger();

	/**
	 * Assignment operator
	 * 
	 * \param from the QBigInteger to copy from
	 *
	 * \code
	 * QBigInteger a; // a is zero
	 * QBigInteger b( 500 );
	 * a = b; // a is now 500
	 * \endcode
	 */
	QBigInteger & operator=(const QBigInteger &from);

	/**
	 * \overload
	 *
	 * \param s the QString containing an integer representation
	 *
	 * \sa bool fromString(const QString &s)
	 *
	 * \note it is the application's responsibility to make sure
	 * that the QString represents a valid integer (ie it only
	 * contains numbers and an optional minus sign at the start)
	 * 
	 **/
	QBigInteger & operator=(const QString &s);

	/**
	 * Increment in place operator
	 *
	 * \param b the amount to increment by
	 *
	 * \code
	 * QBigInteger a; // a is zero
	 * QBigInteger b( 500 );
	 * a += b; // a is now 500
	 * a += b; // a is now 1000
	 * \endcode
	 **/
	QBigInteger & operator+=(const QBigInteger &b);

	/**
	 * Decrement in place operator
	 *
	 * \param b the amount to decrement by
	 *
	 * \code
	 * QBigInteger a; // a is zero
	 * QBigInteger b( 500 );
	 * a -= b; // a is now -500
	 * a -= b; // a is now -1000
	 * \endcode
	 **/
	QBigInteger & operator-=(const QBigInteger &b);

	/** 
	 * Output %QBigInteger as a QSecureArray
	 */
	QSecureArray toArray() const;

	/**
	 * Assign from a QSecureArray
	 *
	 * \param a a QSecureArray that represents an integer
	 * 
	 * \sa QBigInteger(const QSecureArray &a);
	 */
	void fromArray(const QSecureArray &a);

	/** 
	 * Convert %QBigInteger to a QString
	 *
	 * \code
	 * QString aString;
	 * QBigInteger aBiggishInteger( 5878990 );
	 * aString = aBiggishInteger.toString(); // aString is now "5878990"
	 * \endcode
	 */
	QString toString() const;

	/**
	 * Assign from a QString
	 *
	 * \param s a QString that represents an integer
	 *
	 * \note it is the application's responsibility to make sure
	 * that the QString represents a valid integer (ie it only
	 * contains numbers and an optional minus sign at the start)
	 * 
	 * \sa QBigInteger(const QString &s)
	 * \sa QBigInteger & operator=(const QString &s)
	 */
	bool fromString(const QString &s);

	/** 
	 * Compare this value with another %QBigInteger
	 *
	 * Normally it is more readable to use one of the operator overloads,
	 * so you don't need to use this method directly.
	 *
	 * \param n the QBigInteger to compare with
	 * \param checkSign if true, signs are meaningful; if false, only
	 * magnitude (absolute value) is checked
	 *
	 * \return zero if the values are the same, negative if the argument
	 * is less than the value of this QBigInteger, and positive if the argument
	 * value is greater than this QBigInteger
	 *
	 * \code
	 * QBigInteger a( "400" );
	 * QBigInteger b( "-400" );
	 * QBigInteger c( " 200 " );
	 * int result;
	 * result = a.cmp( b );        // return positive 400 > -400
	 * retult = a.cmp( b, false ); // return zero, magnitudes are the same
	 * result = a.cmp( c );        // return positive,  400 > 200
	 * result = b.cmp( c, true );  // return negative, -400 < 200
	 * result = b.cmp( c, false ); // return positive, abs(-400) > abs(-200)
	 * \endcode
	 **/
	Q_INT32 cmp(const QBigInteger &n, bool checkSign = true) const;
private:
	class Private;
	Private *d;
};

inline bool operator==(const QBigInteger &a, const QBigInteger &b)
{
	return (0 == a.cmp( b ) );
}

inline bool operator!=(const QBigInteger &a, const QBigInteger &b)
{
	return (0 != a.cmp( b ) );
}

inline bool operator<=(const QBigInteger &a, const QBigInteger &b)
{
	return (a.cmp( b ) <= 0 );
}

inline bool operator>=(const QBigInteger &a, const QBigInteger &b)
{
	return (a.cmp( b ) >= 0 );
}

inline bool operator<(const QBigInteger &a, const QBigInteger &b)
{
	return (a.cmp( b ) < 0 );
}

inline bool operator>(const QBigInteger &a, const QBigInteger &b)
{
	return (a.cmp( b ) > 0 );
}

QTextStream &operator<<(QTextStream &stream, const QBigInteger &b);


namespace QCA
{
	class Provider;
	class Random;
	typedef QPtrList<Provider> ProviderList;
	typedef QPtrListIterator<Provider> ProviderListIterator;

	/** 
	 * A list of the capabilities available within QCA
	 *
	 * If you are adding another capability to QCA, note that the
	 * bit mask approach needs to be maintained, since the plugins
	 * return the capabilities that they support as a single
	 * integer value, where each support capability is represented
	 * by a bit set to true.
	 */
	enum
	{
		CAP_SHA1      = 0x0001, /**< SHA-1 digest hash (SHA1) */
		CAP_SHA256    = 0x0002, /**< SHA-256 digest hash, per
					 * FIPS 180-2 (SHA256) */
		CAP_MD5       = 0x0004, /**< %MD5 digest hash, per
					 * RFC1321 (MD5) */
		CAP_BlowFish  = 0x0008, /**< %BlowFish cipher (BlowFish)*/
		CAP_TripleDES = 0x0010, /**< Triple DES cipher (TripleDES) */
		CAP_AES128    = 0x0020, /**< AES cipher, 128 bits (AES128)*/
		CAP_AES256    = 0x0040, /**< AES cipher, 256 bits (AES256)*/
		CAP_RSA       = 0x0080, /**< RSA */
		CAP_X509      = 0x0100, /**< X509 certificate*/
		CAP_TLS       = 0x0200, /**< Secure Socket Layer */
		CAP_SASL      = 0x0400, /**< Simple Authentication and
					 * Security Layer, per RFC2222 (SASL) */
		CAP_SHA0      = 0x0800, /**< SHA-0 digest hash (SHA0)*/
		CAP_MD2       = 0x1000, /**< %MD2 digest hash, per
					 * RFC1319 (MD2) */
		CAP_MD4       = 0x2000, /**< %MD4 digest hash, per
					 * RFC1320 (MD4) */
		CAP_RIPEMD160 = 0x4000, /**< RIPEMD digest hash, 160 bits (RIPEMD160)*/
	}; // to be obsoleted

	/**
	 * Mode settings for cipher algorithms
	 */
	enum Mode
	{
		CBC = 0x0001, /**< operate in %Cipher Block Chaining mode */
		CFB = 0x0002  /**< operate in %Cipher FeedBack mode */
	};

	/**
	 * Direction settings for cipher algorithms
	 */
	enum
	{
		Encrypt = 0x0001, /**< cipher algorithm should encrypt */
		Decrypt = 0x0002  /**< cipher algorithm should decrypt */
	};

	enum MemoryMode
	{
		Practical, /**< mlock and drop root if available, else mmap */
		Locking, /**< mlock and drop root */
		LockingKeepPrivileges /**< mlock */
	};

	enum Direction
	{
		Encode,
		Decode
	};

	enum DL_Group {
		DSA_512,
		DSA_768,
		DSA_1024,
		IETF_768,
		IETF_1024,
		IETF_1536,
		IETF_2048,
		IETF_3072,
		IETF_4096
	};

	/**
	 * Initialise the QCA plugin system.
	 *
	 * This must be the first QCA call that you make in your
	 * application.
	 */
	QCA_EXPORT void init();
	QCA_EXPORT void init(MemoryMode m, int prealloc);

	QCA_EXPORT void deinit();
	QCA_EXPORT bool haveSecureMemory();

	/**
	 * Test if a capability (algorithm) is available.
	 *
	 * Since capabilities are made available at runtime, you
	 * should always check before using a capability the first
	 * time, as shown below.
	 * \code
	 * QCA::init();
         * if(!QCA::isSupported(QCA::CAP_SHA1))
         *     printf("SHA1 not supported!\n");
	 * else {
         *     QString result = QCA::SHA1::hashToString(myString);
         *     printf("sha1(\"%s\") = [%s]\n", myString.data(), result.latin1());
	 * }
	 * \endcode
	 */
	QCA_EXPORT bool isSupported(int capabilities); // to be obsoleted
	QCA_EXPORT void insertProvider(QCAProvider *); // to be obsoleted

	// version 2 global functions
	QCA_EXPORT bool isSupported(const QStringList &features);
	QCA_EXPORT bool isSupported(const QString &features);
	QCA_EXPORT QStringList supportedFeatures();
	QCA_EXPORT QStringList defaultFeatures();
	QCA_EXPORT bool insertProvider(Provider *p, int priority = 0);
	QCA_EXPORT void setProviderPriority(const QString &name, int priority);
	QCA_EXPORT const ProviderList & providers();
	QCA_EXPORT void unloadAllPlugins();

	QCA_EXPORT Random & globalRNG();
	QCA_EXPORT void setGlobalRNG(const QString &provider);

	/** 
	 * Convert a QByteArray to printable hexadecimal
	 * representation.
	 *
	 * This is a convenience function to convert an arbitrary
	 * QByteArray to a printable representation.
	 *
	 * \code
	 * 	QCA::init();
	 * 	QByteArray test(10);
	 *	test.fill('a');
	 * 	// 0x61 is 'a' in ASCII
	 *	if (QString("61616161616161616161") == QCA::arrayToHex(test) ) {
	 *		printf ("arrayToHex passed\n");
	 *	}
	 * \endcode
	 *
	 * \param array an array to be converted
	 * \return a printable representation
	 */
	QCA_EXPORT QString arrayToHex(const QByteArray &array); // to be obsoleted
	QCA_EXPORT QString arrayToHex(const QSecureArray &array);

	/**
	 * Convert a QString containing a hexadecimal representation
	 * of a byte array into a QByteArray
	 *
	 * This is a convenience function to convert a printable
	 * representation into a QByteArray - effectively the inverse
	 * of QCA::arrayToHex.
	 *
	 * \code
	 * 	QCA::init();
	 * 	QByteArray test(10);
	 *
	 *	test.fill('b'); // 0x62 in hexadecimal
	 *	test[7] = 0x00; // can handle strings with nulls
	 *
	 *	if (QCA::hexToArray(QString("62626262626262006262") ) == test ) {
	 *		printf ("hexToArray passed\n");
	 *	}
	 * \endcode
	 *
	 * \param hexString the string containing a printable
	 * representation to be converted
	 * \return the equivalent QByteArray
	 *
		
	 */
	QCA_EXPORT QByteArray hexToArray(const QString &hexString);

	class QCA_EXPORT Initializer
	{
	public:
		// botan prefers mmap over locking, so we will too
		Initializer(MemoryMode m = Practical, int prealloc = 64);
		~Initializer();
	};

	// version 2 stuff
	class QCA_EXPORT KeyLength
	{
	public:
		KeyLength(int min, int max, int multiple) { _min = min, _max = max, _multiple = multiple; }

		int minimum() const { return _min; }
		int maximum() const { return _max; }
		int multiple() const { return _multiple; }

	private:
		int _min, _max, _multiple;
	};

	class QCA_EXPORT Provider
	{
	public:
		virtual ~Provider();

		class Context
		{
		public:
			Context(Provider *parent, const QString &type);
			virtual ~Context();

			Provider *provider() const;
			QString type() const;
			virtual Context *clone() const = 0;
			bool sameProvider(Context *c);

			int refs;

		private:
			Provider *_provider;
			QString _type;
		};

		virtual void init();
		virtual QString name() const = 0;
		virtual QStringList features() const = 0;
		virtual Context *createContext(const QString &type) = 0;
	};

	class QCA_EXPORT BufferedComputation
	{
	public:
		virtual ~BufferedComputation();

		virtual void clear() = 0;
		virtual void update(const QSecureArray &a) = 0;
		virtual QSecureArray final() = 0;
		QSecureArray process(const QSecureArray &a);
	};

	class QCA_EXPORT Filter
	{
	public:
		virtual ~Filter();

		virtual void clear() = 0;
		virtual QSecureArray update(const QSecureArray &a) = 0;
		virtual QSecureArray final() = 0;
		virtual bool ok() const = 0;
		QSecureArray process(const QSecureArray &a);
	};

	class QCA_EXPORT TextFilter : public Filter
	{
	public:
		TextFilter(Direction dir);

		void setup(Direction dir);
		QSecureArray encode(const QSecureArray &a);
		QSecureArray decode(const QSecureArray &a);
		QString arrayToString(const QSecureArray &a);
		QSecureArray stringToArray(const QString &s);
		QString encodeString(const QString &s);
		QString decodeString(const QString &s);

	protected:
		Direction _dir;
	};

	class QCA_EXPORT Hex : public TextFilter
	{
	public:
		Hex(Direction dir = Encode);

		virtual void clear();
		virtual QSecureArray update(const QSecureArray &a);
		virtual QSecureArray final();
		virtual bool ok() const;

	private:
		uchar val;
		bool partial;
		bool _ok;
	};

	class QCA_EXPORT Base64 : public TextFilter
	{
	public:
		Base64(Direction dir = Encode);

		virtual void clear();
		virtual QSecureArray update(const QSecureArray &a);
		virtual QSecureArray final();
		virtual bool ok() const;

	private:
		QSecureArray partial;
		bool _ok;
	};

	class QCA_EXPORT Algorithm
	{
	public:
		Algorithm(const Algorithm &from);
		virtual ~Algorithm();

		Algorithm & operator=(const Algorithm &from);

		QString type() const;
		Provider *provider() const;
		void detach();

	protected:
		Algorithm();
		Algorithm(const QString &type, const QString &provider);
		Provider::Context *context() const;
		void change(Provider::Context *c);
		void change(const QString &type, const QString &provider);

	private:
		class Private;
		Private *d;
	};

	class QCA_EXPORT Random : public Algorithm
	{
	public:
		enum Quality { Nonce, PublicValue, SessionKey, LongTermKey };
		Random(const QString &provider="");

		uchar nextByte(Quality q = SessionKey);
		QSecureArray nextBytes(int size, Quality q = SessionKey);

		static uchar randomChar(Quality q = SessionKey);
		static uint randomInt(Quality q = SessionKey);
		static QSecureArray randomArray(int size, Quality q = SessionKey);
	};

	class QCA_EXPORT SymmetricKey : public QSecureArray
	{
	public:
		SymmetricKey();
		SymmetricKey(int size);
		SymmetricKey(const QSecureArray &a);

		SymmetricKey & operator=(const QSecureArray &a);
	};
	bool operator==(const SymmetricKey &a, const SymmetricKey &b);
	bool operator!=(const SymmetricKey &a, const SymmetricKey &b);

	class QCA_EXPORT InitializationVector : public QSecureArray
	{
	public:
		InitializationVector();
		InitializationVector(int size);
		InitializationVector(const QSecureArray &a);

		InitializationVector & operator=(const QSecureArray &a);
	};

	/**
	 * General superclass for hashing algorithms.
	 *
	 * %Hash is a superclass for the various hashing algorithms
	 * within QCA. You should not need to use it directly unless you are
	 * adding another hashing capability to QCA - you should be
	 * using a sub-class. SHA1 or RIPEMD160 are recommended for
	 * new applications, although MD2, MD4, MD5 or SHA0 may be
	 * applicable (for interoperability reasons) for some
	 * applications. If you are adding another hashing algorithm,
	 * you need to derive from both this class and from
	 * HashStatic.
	 *
	 * To perform a hash, you create an object (of one of the
	 * sub-classes of Hash), call update() with the data that
	 * needs to be hashed, and then call final(), which returns
	 * a QByteArray of the hash result. An example (using the SHA1
	 * hash, with 1000 updates of a 1000 byte string) is shown below:
	 * \code
	 *        if(!QCA::isSupported(QCA::CAP_SHA1))
	 *                printf("SHA1 not supported!\n");
	 *        else {
	 *                QByteArray fillerString;
	 *                fillerString.fill('a', 1000);
	 *
	 *                QCA::SHA1 shaHash;
	 *                for (int i=0; i<1000; i++)
	 *                        shaHash.update(fillerString);
	 *                QByteArray hashResult = shaHash.final();
	 *                if ( "34aa973cd4c4daa4f61eeb2bdbad27316534016f" == QCA::arrayToHex(hashResult) ) {
	 *                        printf("big SHA1 is OK\n");
	 *                } else {
	 *                        printf("big SHA1 failed\n");
	 *                }
	 *        }
	 * \endcode
	 *
	 * If you only have a simple hash requirement - a single
	 * string that is fully available in memory at one time - 
	 * then you may be better off with one of the static
	 * methods. So, for example, instead of creating a QCA::SHA1
	 * or QCA::MD5 object, then doing a single update() and the final()
	 * call; you simply call QCA::SHA1::hash() or
	 * QCA::MD5::hash() with the data that you would otherwise
	 * have provided to the update() call.
	 */
	class QCA_EXPORT Hash
	{
	public:
		/**
		 * Constructs a copy of the Hash parameter.
		 *
		 * \param fromHash a Hash (or Hash sub-class) to copy
		 */
		Hash(const Hash &fromHash);

		/**
		 * Assigns the internal state data from the fromHash
		 * parameter to this Hash. 
		 *
		 * \param fromHash a Hash (or Hash sub-class) to copy
		 */
		Hash & operator=(const Hash &fromHash);

		~Hash();

		/**
		 * Reset a hash, dumping all previous parts of the
		 * message.
		 *
		 * This method clears (or resets) the hash algorithm,
		 * effectively undoing any previous update()
		 * calls. You should use this call if you are re-using
		 * a Hash sub-class object to calculate additional
		 * hashes.
		 */
		void clear();

		/**
		 * Update a hash, adding more of the message contents
		 * to the digest. The whole message needs to be added
		 * using this method before you call final(). 
		 *
		 * If you find yourself only calling update() once,
		 * you may be better off using a static method
		 * instead.
		 *
		 */
		void update(const QByteArray &array);

		/**
		 * Finalises input and returns the hash result
		 *
		 * After calling update() with the required data, the
		 * hash results are finalised and produced.
		 *
		 * Note that it is not possible to add further data (with
		 * update()) after calling final(), because of the way
		 * the hashing works - null bytes are inserted to pad
		 * the results up to a fixed size. If you want to
		 * reuse the Hash object, you should call clear() and
		 * start to update() again.
		 */
		QByteArray final();

	protected:
		Hash(QCA_HashContext *);

	private:
		class Private;
		Private *d;
	};

	/**
	 * General superclass for static methods for hashing
	 * algorithms
	 *
	 * %HashStatic is a superclass for the various hashing algorithms
	 * within QCA. You should not need to use it directly unless you are
	 * adding another hashing capability to QCA - you should be
	 * using a sub-class. SHA1 or RIPEMD160 are recommended for
	 * new applications, although MD2, MD4, MD5 or SHA0 may be
	 * applicable (for interoperability reasons) for some
	 * applications.  If you are adding another hashing algorithm,
	 * you need to derive from both this class and from
	 * Hash.
	 */
	template <class T>
	class QCA_EXPORT HashStatic
	{
	public:
		HashStatic<T>() {}

		/**
		 * %Hash a QByteArray, returning it as another
		 * QByteArray.
		 * 
		 * This is a convenience static method that returns the
		 * hash of a QByteArray.
		 * 
		 * \code
		 * QByteArray sampleArray(3);
		 * sampleArray.fill('a');
		 * QByteArray outputArray = QCA::MD2::hash(sampleArray);
		 * \endcode
		 * 
		 * \param array the QByteArray to hash
		 *
		 * If you need more flexibility,
		 * consider creating an Hash sub-class object, and calling
		 * update() and final().
		 */
		static QByteArray hash(const QByteArray &array)
		{
			T obj;
			obj.update(array);
			return obj.final();
		}

		/**
		 * \overload
		 *
		 * \param cs the QCString to hash
		 */
		static QByteArray hash(const QCString &cs)
		{
			QByteArray a(cs.length());
			memcpy(a.data(), cs.data(), a.size());
			return hash(a);
		}

		/**
		 * %Hash a QByteArray, returning it as a printable
		 * string
		 * 
		 * This is a convenience method that returns the
		 * hash of a QByteArray as a hexadecimal
		 * representation encoded in a QString.
		 * 
		 * \param array the QByteArray to hash
		 *
		 * If you need more flexibility, you can create a Hash
		 * sub-class object, call Hash::update() as
		 * required, then call Hash::final(), before using the static arrayToHex() method.
		 */
		static QString hashToString(const QByteArray &array)
		{
			return arrayToHex(hash(array));
		}

		/**
		 * \overload
		 *
		 * \code
		 *        QCA::init();
		 *        QCString cs = (argc >= 2) ? argv[1] : "hello";
		 *
		 *        if(!QCA::isSupported(QCA::CAP_SHA1))
		 *                printf("SHA1 not supported!\n");
		 *        else {
		 *                QString result = QCA::SHA1::hashToString(cs);
		 *                printf("sha1(\"%s\") = [%s]\n", cs.data(), result.latin1());
		 *        }
		 * \endcode
		 *
		 * which will produce:
		 *
		 * \verbatim sha1("hello") = [aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d] \endverbatim
		 *
		 * \param cs the QCString to hash		 
		 */
		static QString hashToString(const QCString &cs)
		{
			return arrayToHex(hash(cs));
		}
	};

	class QCA_EXPORT Cipher
	{
	public:
		Cipher(const Cipher &);
		Cipher & operator=(const Cipher &);
		~Cipher();

		QByteArray dyn_generateKey(int size=-1) const;
		QByteArray dyn_generateIV() const;
		void reset(int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad=true);
		bool update(const QByteArray &a);
		QByteArray final(bool *ok=0);

	protected:
		Cipher(QCA_CipherContext *, int dir, int mode, const QByteArray &key, const QByteArray &iv, bool pad);

	private:
		class Private;
		Private *d;
	};

	template <class T>
	class QCA_EXPORT CipherStatic
	{
	public:
		CipherStatic<T>() {}

		static QByteArray generateKey(int size=-1)
		{
			T obj;
			return obj.dyn_generateKey(size);
		}

		static QByteArray generateIV()
		{
			T obj;
			return obj.dyn_generateIV();
		}
	};

	class QCA_EXPORT MessageAuthenticationCode : public Algorithm, public BufferedComputation
	{
	public:
		MessageAuthenticationCode(const MessageAuthenticationCode &from);
		~MessageAuthenticationCode();
		MessageAuthenticationCode & operator=(const MessageAuthenticationCode &from);

		KeyLength keyLength() const;
		bool validKeyLength(int n) const;

		virtual void clear();
		virtual void update(const QSecureArray &a);
		virtual QSecureArray final();

		void setup(const SymmetricKey &key);

	protected:
		MessageAuthenticationCode(const QString &type, const SymmetricKey &key, const QString &provider);

	private:
		class Private;
		Private *d;
	};

	//class QCA_EXPORT HMAC : public MessageAuthenticationCode
	//{
	//public:
	//	HMAC(const Hash &h = SHA1(), const SymmetricKey &key = SymmetricKey(), const QString &provider="") : MessageAuthenticationCode(subAlg("hmac", h.type()), key, provider) {}
	//};

	/**
	 * SHA-0 cryptographic message digest hash algorithm.
	 *
	 * %SHA0 is a 160 bit hashing function, no longer recommended
	 * for new applications because of known (partial) attacks
	 * against it.
	 *
	 * You can use this class in two basic ways - standard member
	 * methods, and static convenience methods. Both are shown in
	 * the example below.
	 *
	 * \code
	 *        if(!QCA::isSupported(QCA::CAP_SHA0))
	 *                printf("SHA0 not supported!\n");
	 *        else {
	 *                // Static convenience method.
	 *                // QCA::SHA0::hash() might be handy too.
	 *                QCString actualResult;
	 *                actualResult = QCA::SHA0::hashToString(message);
	 *
	 *                // normal methods - update() and final()
	 *                QByteArray fillerString;
	 *                fillerString.fill('a', 1000);
	 *                QCA::SHA0 shaHash;
	 *                for (int i=0; i<1000; i++)
	 *                        shaHash.update(fillerString);
	 *                QByteArray hashResult = shaHash.final();
	 *        }
	 * \endcode
	 *
	 * \since QCA 1.1
	 */
	class QCA_EXPORT SHA0 : public Hash, public HashStatic<SHA0>
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a SHA-0 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using a static
		 * method, such as QCA::SHA0::hash()
		 */
		SHA0();
	};

	/**
	 * SHA-1 cryptographic message digest hash algorithm.
	 *
	 * This algorithm takes an arbitrary data stream, known as the
	 * message (up to \f$2^{64}\f$ bits in length) and outputs a
	 * condensed 160 bit (20 byte) representation of that data
	 * stream, known as the message digest.
	 *
	 * This algorithm is considered secure in that it is considered
	 * computationally infeasible to find the message that
	 * produced the message digest.
	 *
	 * You can use this class in two basic ways - standard member
	 * methods, and static convenience methods. Both are shown in
	 * the example below.
	 *
	 * \code
	 *        if(!QCA::isSupported(QCA::CAP_SHA1))
	 *                printf("SHA1 not supported!\n");
	 *        else {
	 *                // Static convenience method.
	 *                // QCA::SHA1::hash() might be handy too.
	 *                QCString actualResult;
	 *                actualResult = QCA::SHA1::hashToString(message);
	 *
	 *                // normal methods - update() and final()
	 *                QByteArray fillerString;
	 *                fillerString.fill('a', 1000);
	 *                QCA::SHA1 shaHash;
	 *                for (int i=0; i<1000; i++)
	 *                        shaHash.update(fillerString);
	 *                QByteArray hashResult = shaHash.final();
	 *        }
	 * \endcode
	 *
	 * For more information, see Federal Information Processing
	 * Standard Publication 180-2 "Specifications for the Secure
	 * %Hash Standard", available from http://csrc.nist.gov/publications/
	 */
	class QCA_EXPORT SHA1 : public Hash, public HashStatic<SHA1>
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a SHA-1 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using a static
		 * method, such as QCA::SHA1::hash()
		 */
		SHA1();
	};

	/**
	 * SHA-256 cryptographic message digest hash algorithm.
	 *
	 * This algorithm takes an arbitrary data stream, known as the
	 * message (up to \f$2^{64}\f$ bits in length) and outputs a
	 * condensed 256 bit (32 byte) representation of that data
	 * stream, known as the message digest.
	 *
	 * This algorithm is considered secure in that it is considered
	 * computationally infeasible to find the message that
	 * produced the message digest.
	 *
	 * For more information, see Federal Information Processing
	 * Standard Publication 180-2 "Specifications for the Secure
	 * %Hash Standard", available from http://csrc.nist.gov/publications/
	 */
	class QCA_EXPORT SHA256 : public Hash, public HashStatic<SHA256>
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a SHA-256 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using a static
		 * method, such as QCA::SHA256::hash()
		 */
		SHA256();
	};

	/**
	 * %MD2 cryptographic message digest hash algorithm.
	 *
	 * This algorithm takes an arbitrary data stream, known as the
	 * message and outputs a
	 * condensed 128 bit (16 byte) representation of that data
	 * stream, known as the message digest.
	 *
	 * This algorithm is considered slightly more secure than MD5,
	 * but is more expensive to compute. Unless backward
	 * compatibility or interoperability are considerations, you
	 * are better off using the SHA1 or RIPEMD160 hashing algorithms.
	 *
	 * For more information, see B. Kalinski RFC1319 "The %MD2
	 * Message-Digest Algorithm".
	 */
	class QCA_EXPORT MD2 : public Hash, public HashStatic<MD2>
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a MD2 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using a static
		 * method, such as QCA::MD2::hash().
		 */
		MD2();
	};

	/**
	 * %MD4 cryptographic message digest hash algorithm.
	 *
	 * This algorithm takes an arbitrary data stream, known as the
	 * message and outputs a
	 * condensed 128 bit (16 byte) representation of that data
	 * stream, known as the message digest.
	 *
	 * This algorithm is not considered to be secure, based on
	 * known attacks. It should only be used for
	 * applications where collision attacks are not a
	 * consideration (for example, as used in the rsync algorithm
	 * for fingerprinting blocks of data). If a secure hash is
	 * required, you are better off using the SHA1 or RIPEMD160
	 * hashing algorithms. MD2 and MD5 are both stronger 128 bit
	 * hashes.
	 *
	 * For more information, see R. Rivest RFC1320 "The %MD4
	 * Message-Digest Algorithm".
	 */
	class QCA_EXPORT MD4 : public Hash, public HashStatic<MD4>
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a MD4 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using a static
		 * method, such as QCA::MD4::hash().
		 */
		MD4();
	};

	/**
	 * %MD5 cryptographic message digest hash algorithm.
	 *
	 * This algorithm takes an arbitrary data stream, known as the
	 * message and outputs a
	 * condensed 128 bit (16 byte) representation of that data
	 * stream, known as the message digest.
	 *
	 * This algorithm is not considered to be secure, based on
	 * known attacks. It should only be used for
	 * applications where collision attacks are not a
	 * consideration. If a secure hash is
	 * required, you are better off using the SHA1 or RIPEMD160
	 * hashing algorithms.
	 *
	 * For more information, see R. Rivest RFC1321 "The %MD5
	 * Message-Digest Algorithm".
	 */
	class QCA_EXPORT MD5 : public Hash, public HashStatic<MD5>
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a MD5 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using a static
		 * method, such as QCA::MD5::hash()
		 */
		MD5();
	};

	/**
	 * %RIPEMD160 cryptographic message digest hash algorithm.
	 *
	 * This algorithm takes an arbitrary data stream, known as the
	 * message (up to \f$2^{64}\f$ bits in length) and outputs a
	 * condensed 160 bit (20 byte) representation of that data
	 * stream, known as the message digest.
	 *
	 * This algorithm is considered secure in that it is considered
	 * computationally infeasible to find the message that
	 * produced the message digest.
	 *
	 * You can use this class in two basic ways - standard member
	 * methods, and static convenience methods. Both are shown in
	 * the example below.
	 *
	 * \code
	 *        if(!QCA::isSupported(QCA::CAP_RIPEMD160))
	 *                printf("RIPEMD-160 not supported!\n");
	 *        else {
	 *                // Static convenience method.
	 *                // QCA::RIPEMD160::hash() might be handy too.
	 *                QCString actualResult;
	 *                actualResult = QCA::RIPEMD160::hashToString(message);
	 *
	 *                // normal methods - update() and final()
	 *                QByteArray fillerString;
	 *                fillerString.fill('a', 1000);
	 *                QCA::RIPEMD160 ripemdHash;
	 *                for (int i=0; i<1000; i++)
	 *                        ripemdHash.update(fillerString);
	 *                QByteArray hashResult = ripemdHash.final();
	 *        }
	 * \endcode
	 *
	 */
	class QCA_EXPORT RIPEMD160 : public Hash, public HashStatic<RIPEMD160>
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a RIPEMD160 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using a static
		 * method, such as QCA::RIPEMD160::hash()
		 */
		RIPEMD160();
	};

	class QCA_EXPORT BlowFish : public Cipher, public CipherStatic<BlowFish>
	{
	public:
		BlowFish(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray(), bool pad=true);
	};

	class QCA_EXPORT TripleDES : public Cipher, public CipherStatic<TripleDES>
	{
	public:
		TripleDES(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray(), bool pad=true);
	};

	class QCA_EXPORT AES128 : public Cipher, public CipherStatic<AES128>
	{
	public:
		AES128(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray(), bool pad=true);
	};

	class QCA_EXPORT AES256 : public Cipher, public CipherStatic<AES256>
	{
	public:
		AES256(int dir=Encrypt, int mode=CBC, const QByteArray &key=QByteArray(), const QByteArray &iv=QByteArray(), bool pad=true);
	};

	class RSA;

	class QCA_EXPORT RSAKey
	{
	public:
		RSAKey();
		RSAKey(const RSAKey &from);
		RSAKey & operator=(const RSAKey &from);
		~RSAKey();

		bool isNull() const;
		bool havePublic() const;
		bool havePrivate() const;

		QByteArray toDER(bool publicOnly=false) const;
		bool fromDER(const QByteArray &a);

		QString toPEM(bool publicOnly=false) const;
		bool fromPEM(const QString &);

		// only call if you know what you are doing
		bool fromNative(void *);

	private:
		class Private;
		Private *d;

		friend class RSA;
		friend class TLS;
		bool encrypt(const QByteArray &a, QByteArray *out, bool oaep) const;
		bool decrypt(const QByteArray &a, QByteArray *out, bool oaep) const;
		bool generate(unsigned int bits);
	};

	class QCA_EXPORT RSA
	{
	public:
		RSA();
		~RSA();

		RSAKey key() const;
		void setKey(const RSAKey &);

		bool encrypt(const QByteArray &a, QByteArray *out, bool oaep=false) const;
		bool decrypt(const QByteArray &a, QByteArray *out, bool oaep=false) const;

		static RSAKey generateKey(unsigned int bits);

	private:
		RSAKey v_key;
	};

	typedef QMap<QString, QString> CertProperties;

	class QCA_EXPORT Cert
	{
	public:
		Cert();
		Cert(const Cert &);
		Cert & operator=(const Cert &);
		~Cert();

		bool isNull() const;

		QString commonName() const;
		QString serialNumber() const;
		QString subjectString() const;
		QString issuerString() const;
		CertProperties subject() const;
		CertProperties issuer() const;
		QDateTime notBefore() const;
		QDateTime notAfter() const;

		QByteArray toDER() const;
		bool fromDER(const QByteArray &a);

		QString toPEM() const;
		bool fromPEM(const QString &);

	private:
		class Private;
		Private *d;

		friend class TLS;
		void fromContext(QCA_CertContext *);
	};

	class QCA_EXPORT TLS : public QObject
	{
		Q_OBJECT
	public:
		enum Validity
		{
			NoCert,
			Valid,
			HostMismatch,
			Rejected,
			Untrusted,
			SignatureFailed,
			InvalidCA,
			InvalidPurpose,
			SelfSigned,
			Revoked,
			PathLengthExceeded,
			Expired,
			Unknown
		};
		enum Error { ErrHandshake, ErrCrypt };

		TLS(QObject *parent=0);
		~TLS();

		void setCertificate(const Cert &cert, const RSAKey &key);
		void setCertificateStore(const QPtrList<Cert> &store);  // note: store must persist

		void reset();
		bool startClient(const QString &host="");
		bool startServer();
		void close();
		bool isHandshaken() const;

		// plain (application side)
		void write(const QByteArray &a);
		QByteArray read();

		// encoded (socket side)
		void writeIncoming(const QByteArray &a);
		QByteArray readOutgoing();
		QByteArray readUnprocessed();

		// cert related
		const Cert & peerCertificate() const;
		int certificateValidityResult() const;

	signals:
		void handshaken();
		void readyRead();
		void readyReadOutgoing(int plainBytes);
		void closed();
		void error(int);

	private slots:
		void update();

	private:
		class Private;
		Private *d;
	};

	class QCA_EXPORT SASL : public QObject
	{
		Q_OBJECT
	public:
		enum Error { ErrAuth, ErrCrypt };
		enum ErrorCond
		{
			NoMech,
			BadProto,
			BadServ,
			BadAuth,
			NoAuthzid,
			TooWeak,
			NeedEncrypt,
			Expired,
			Disabled,
			NoUser,
			RemoteUnavail
		};
		SASL(QObject *parent=0);
		~SASL();

		static void setAppName(const QString &name);

		void reset();
		int errorCondition() const;

		// options
		void setAllowPlain(bool);
		void setAllowAnonymous(bool);
		void setAllowActiveVulnerable(bool);
		void setAllowDictionaryVulnerable(bool);
		void setRequireForwardSecrecy(bool);
		void setRequirePassCredentials(bool);
		void setRequireMutualAuth(bool);

		void setMinimumSSF(int);
		void setMaximumSSF(int);
		void setExternalAuthID(const QString &authid);
		void setExternalSSF(int);

		void setLocalAddr(const QHostAddress &addr, Q_UINT16 port);
		void setRemoteAddr(const QHostAddress &addr, Q_UINT16 port);

		// initialize
		bool startClient(const QString &service, const QString &host, const QStringList &mechlist, bool allowClientSendFirst=true);
		bool startServer(const QString &service, const QString &host, const QString &realm, QStringList *mechlist);

		// authentication
		void putStep(const QByteArray &stepData);
		void putServerFirstStep(const QString &mech);
		void putServerFirstStep(const QString &mech, const QByteArray &clientInit);
		void setUsername(const QString &user);
		void setAuthzid(const QString &auth);
		void setPassword(const QString &pass);
		void setRealm(const QString &realm);
		void continueAfterParams();
		void continueAfterAuthCheck();

		// security layer
		int ssf() const;
		void write(const QByteArray &a);
		QByteArray read();
		void writeIncoming(const QByteArray &a);
		QByteArray readOutgoing();

	signals:
		// for authentication
		void clientFirstStep(const QString &mech, const QByteArray *clientInit);
		void nextStep(const QByteArray &stepData);
		void needParams(bool user, bool authzid, bool pass, bool realm);
		void authCheck(const QString &user, const QString &authzid);
		void authenticated();

		// for security layer
		void readyRead();
		void readyReadOutgoing(int plainBytes);

		// error
		void error(int);

	private slots:
		void tryAgain();

	private:
		class Private;
		Private *d;

		void handleServerFirstStep(int r);
	};
};

#endif
