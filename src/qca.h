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
 * \mainpage Qt Cryptographic Architecture
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
 * QString hash = QCA::SHA1().hashToString(blockOfData);
 * \endcode
 */

// Direct secure memory access.  For interfacing with C libraries if needed.
QCA_EXPORT void *qca_secure_alloc(int bytes);
QCA_EXPORT void qca_secure_free(void *p);

/**
 * Secure array of bytes
 *
 * The %QSecureArray provides an array of memory from a pool that is, 
 * at least partly, secure. In this sense, secure means that the contents
 * of the memory should not be made available to other applications. By
 * comparison, a QMemArray (or subclass such as QCString or QByteArray) may
 * be held in pages that are free'd without being cleared first. This means
 * that a malicious application can just repeatedly request pages of memory,
 * searching for something that could be of value.
 *
 * Note that this class is implicitly shared (that is, copy on write).
 **/ 
QCA_EXPORT class QSecureArray
{
public:
	/**
	 * Construct a secure byte array, zero length
	 */
	QSecureArray();

	/**
	 * Construct a secure byte array of the specified length
	 *
	 * \param size the number of bytes in the array
	 */
	QSecureArray(int size);

	/**
	 * Construct a secure byte array from a QByteArray
	 *
	 * Note that this copies, rather than references the source array
	 *
	 * \sa operator=()
	 */
	QSecureArray(const QByteArray &a);

	/**
	 * Construct a (shallow) copy of another secure byte array
	 *
	 * \param from the source of the data and length.
	 */
	QSecureArray(const QSecureArray &from);

	~QSecureArray();

	/** 
	 * Creates a reference, rather than a deep copy.
	 * if you want a deep copy then you should use copy()
	 * instead, or use operator=(), then call detach() when required.
	 */
	QSecureArray & operator=(const QSecureArray &from);

	/**
	 * Creates a copy, rather than references
	 *
	 * \param a the array to copy from
	 */
	QSecureArray & operator=(const QByteArray &a);

	/**
	 * Returns a reference to the byte at the index position
	 *
	 * \param index the zero-based offset to obtain
	 */
	char & operator[](int index);

	/**
	 * Returns a reference to the byte at the index position
	 *
	 * \param index the zero-based offset to obtain
	 */
	const char & operator[](int index) const;

	/**
	 * Pointer the data in the secure array
	 * 
	 * You can use this for memcpy and similar functions. If you are trying
	 * to obtain data at a particular offset, you might be better off using
	 * at() or operator[]
	 *
	 */
	char *data() const;

	/**
	 * Returns a reference to the byte at the index position
	 *
	 * \param index the zero-based offset to obtain
	 */
	const char & at(uint index) const;

	/**
	 * Returns a reference to the byte at the index position
	 *
	 * \param index the zero-based offset to obtain
	 */
	char & at(uint index);

	/**
	 * Return the number of bytes in the array
	 */
	uint size() const;

	/**
	 * Test if the array contains any bytes.
	 * 
	 * This is equivalent to testing (size() != 0). Note that if
	 * the array is allocated, isEmpty() is false (even if no data
	 * has been added)
	 *
	 * \return true if the array has zero length, otherwise false
	 */
	bool isEmpty() const;

	/**
	 * Change the length of this array
	 * If the new length is less than the old length, the extra information
	 * is (safely) discarded. If the new length is equal to or greater than
	 * the old length, the existing data is copied into the array.
	 *
	 * \param size the new length
	 */
	bool resize(uint size);

	/** 
	 * creates a deep copy, rather than a reference
	 * if you want a reference then you should use operator=()
	 */
	QSecureArray copy() const;

	/**
	 * If the current array is shared, this conducts a deep copy, 
	 * otherwise it has no effect.
	 *
	 * \code
	 * QSecureArray myArray = anotherArray; // currently the same
	 * myArray.detach(); // no longer the same data, but a copy
	 * // anything here that affects anotherArray does not affect
	 * // myArray; and vice versa.
	 * \endcode
	 */
	 void detach();

	 /**
	  * Copy the contents of the secure array out to a 
	  * standard QByteArray. Note that this performs a deep copy
	  * of the data.
	  */
	 QByteArray toByteArray() const;

private:
	class Private;
	Private *d;

	void reset();
};

/**
 * Equality operator. Returns true if the two QSecureArray
 * arguments have the same data (and the same length, of course).
 *
 * \relates QSecureArray
 **/
bool operator==(const QSecureArray &a, const QSecureArray &b);

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
	 * Output %QBigInteger as a byte array, useful for storage or
	 * transmission.  The format is a binary integer in sign-extended
	 * network-byte-order.
	 *
	 * \sa void fromArray(const QSecureArray &a);
	 */
	QSecureArray toArray() const;

	/**
	 * Assign from an array.  The input is expected to be a binary integer
	 * in sign-extended network-byte-order.
	 *
	 * \param a a QSecureArray that represents an integer
	 *
	 * \sa QBigInteger(const QSecureArray &a);
	 * \sa QSecureArray toArray() const;
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
	 * result = a.compare( b );        // return positive 400 > -400
	 * result = a.compare( c );        // return positive,  400 > 200
	 * result = b.compare( c );        // return negative, -400 < 200
	 * \endcode
	 **/
	int compare(const QBigInteger &n) const;

private:
	class Private;
	Private *d;
};

/**
 * Equality operator. Returns true if the two QBigInteger values
 * are the same, including having the same sign. 
 *
 * \relates QBigInteger
 **/
inline bool operator==(const QBigInteger &a, const QBigInteger &b)
{
	return (0 == a.compare( b ) );
}

/**
 * Inequality operator. Returns true if the two QBigInteger values
 * are different in magnitude, sign or both  
 *
 * \relates QBigInteger
 **/
inline bool operator!=(const QBigInteger &a, const QBigInteger &b)
{
	return (0 != a.compare( b ) );
}

/**
 * Less than or equal operator. Returns true if the QBigInteger value
 * on the left hand side is equal to or less than the QBigInteger value
 * on the right hand side.
 *
 * \relates QBigInteger
 **/
inline bool operator<=(const QBigInteger &a, const QBigInteger &b)
{
	return (a.compare( b ) <= 0 );
}

/**
 * Greater than or equal operator. Returns true if the QBigInteger value
 * on the left hand side is equal to or greater than the QBigInteger value
 * on the right hand side.
 *
 * \relates QBigInteger
 **/
inline bool operator>=(const QBigInteger &a, const QBigInteger &b)
{
	return (a.compare( b ) >= 0 );
}

/**
 * Less than operator. Returns true if the QBigInteger value
 * on the left hand side is less than the QBigInteger value
 * on the right hand side.
 *
 * \relates QBigInteger
 **/
inline bool operator<(const QBigInteger &a, const QBigInteger &b)
{
	return (a.compare( b ) < 0 );
}

/**
 * Greater than operator. Returns true if the QBigInteger value
 * on the left hand side is greater than the QBigInteger value
 * on the right hand side.
 *
 * \relates QBigInteger
 **/
inline bool operator>(const QBigInteger &a, const QBigInteger &b)
{
	return (a.compare( b ) > 0 );
}

/**
 * Stream operator.
 *
 * \relates QBigInteger
 **/
QTextStream &operator<<(QTextStream &stream, const QBigInteger &b);

/** 
 * QCA - the Qt Cryptographic Architecture
 */
namespace QCA
{
	class Provider;
	class Random;
	typedef QPtrList<Provider> ProviderList;
	typedef QPtrListIterator<Provider> ProviderListIterator;

	/**
	 * Mode settings for memory allocation
	 *
	 * QCA can use secure memory, however most operating systems
	 * restrict the amount of memory that can be pinned by user
	 * applications, to prevent a denial-of-service attack. 
	 *
	 * QCA support two approaches to getting memory - the mlock
	 * method, which generally requires root (administrator) level
	 * privileges, and the mmap method which is not as secure, but
	 * which should be able to be used by any process.
	 * 
	 * \sa Initializer
	 */
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

	enum DL_Group
	{
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

	enum CertValidity
	{
		Valid,
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

	enum CertUsage
	{
		Any             = 0x00,
		TLSServer       = 0x01,
		TLSClient       = 0x02,
		CodeSigning     = 0x04,
		EmailProtection = 0x08,
		TimeStamping    = 0x10,
		CRLSigning      = 0x20
	};

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
         * if(!QCA::isSupported("sha1"))
         *     printf("SHA1 not supported!\n");
	 * else {
         *     QString result = QCA::SHA1::hashToString(myString);
         *     printf("sha1(\"%s\") = [%s]\n", myString.data(), result.latin1());
	 * }
	 * \endcode
	 * 
	 * \param features the name of the capability to test for
	 *
	 * \return true if the capability is available, otherwise false
	 *
	 * Note that you can test for a combination of capabilities,
	 * using a comma delimited list:
	 * \code
	 * QCA::isSupported("sha1,md5"):
	 * \endcode
	 * which will return true if all of the capabilities listed
	 * are present.
	 *
	 */
	QCA_EXPORT bool isSupported(const char *features);

	/**
	 * \overload
	 *
	 * \param features a list of features to test for
	 */
	QCA_EXPORT bool isSupported(const QStringList &features);

	/**
	 * Generate a list of all the supported features in plugins,
	 * and in built in capabilities
	 *
	 * \return a list containing the names of the features
	 *
	 * The following code writes a list of features to standard out
	 * \code 
	 * QStringList capabilities;
	 * capabilities = QCA::supportedFeatures();
	 * std::cout << "Supported:" << capabilities.join(",") << std::endl;
	 * \endcode
	 *
	 * \sa isSupported(const char *features)
	 * \sa isSupported(const QStringList &features)
	 * \sa defaultFeatures()
	 */
	QCA_EXPORT QStringList supportedFeatures();

	/**
	 * Generate a list of the built in features. This differs from
	 * supportedFeatures() in that it does not include features provided
	 * by plugins.
	 *
	 * \return a list containing the names of the features
	 *
	 * The following code writes a list of features to standard out
	 * \code 
	 * QStringList capabilities;
	 * capabilities = QCA::defaultFeatures();
	 * std::cout << "Default:" << capabilities.join(",") << std::endl;
	 * \endcode
	 *
	 * \sa isSupported(const char *features)
	 * \sa isSupported(const QStringList &features)
	 * \sa supportedFeatures()
	 */
	QCA_EXPORT QStringList defaultFeatures();
	QCA_EXPORT bool insertProvider(Provider *p, int priority = 0);
	QCA_EXPORT void setProviderPriority(const QString &name, int priority);
	QCA_EXPORT const ProviderList & providers();
	QCA_EXPORT void unloadAllPlugins();

	QCA_EXPORT Random & globalRNG();
	QCA_EXPORT void setGlobalRNG(const QString &provider);

	/**
	 * Convert a byte array to printable hexadecimal
	 * representation.
	 *
	 * This is a convenience function to convert an arbitrary
	 * QSecureArray to a printable representation.
	 *
	 * \code
	 * 	QSecureArray test(10);
	 *	test.fill('a');
	 * 	// 0x61 is 'a' in ASCII
	 *	if (QString("61616161616161616161") == QCA::arrayToHex(test) ) {
	 *		printf ("arrayToHex passed\n");
	 *	}
	 * \endcode
	 *
	 * \param array the array to be converted
	 * \return a printable representation
	 */
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
		Random(const QString &provider = "");

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
	 * applications. 
	 *
	 * To perform a hash, you create an object (of one of the
	 * sub-classes of Hash), call update() with the data that
	 * needs to be hashed, and then call final(), which returns
	 * a QByteArray of the hash result. An example (using the SHA1
	 * hash, with 1000 updates of a 1000 byte string) is shown below:
	 * \code
	 *        if(!QCA::isSupported("sha1"))
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
	 * then you may be better off with one of the convenience
	 * methods. So, for example, instead of creating a QCA::SHA1
	 * or QCA::MD5 object, then doing a single update() and the final()
	 * call; you simply call QCA::SHA1().hash() or
	 * QCA::MD5().hash() with the data that you would otherwise
	 * have provided to the update() call.
	 */
	class QCA_EXPORT Hash : public Algorithm, public BufferedComputation
	{
	public:
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
		virtual void clear();

		/**
		 * Update a hash, adding more of the message contents
		 * to the digest. The whole message needs to be added
		 * using this method before you call final(). 
		 *
		 * If you find yourself only calling update() once,
		 * you may be better off using a convenience method
		 * such as hash() or hashToString() instead.
		 *
		 */
		virtual void update(const QSecureArray &a);

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
		virtual QSecureArray final();

		/**
		 * %Hash a byte array, returning it as another
		 * byte array.
		 * 
		 * This is a convenience method that returns the
		 * hash of a QSecureArray.
		 * 
		 * \code
		 * QSecureArray sampleArray(3);
		 * sampleArray.fill('a');
		 * QSecureArray outputArray = QCA::MD2::hash(sampleArray);
		 * \endcode
		 * 
		 * \param array the QByteArray to hash
		 *
		 * If you need more flexibility (e.g. you are constructing
		 * a large byte array object just to pass it to hash(), then
		 * consider creating an Hash sub-class object, and calling
		 * update() and final().
		 */
		QSecureArray hash(const QSecureArray &array);

		/**
		 * \overload
		 *
		 * \param cs the QCString to hash
		 */
		QSecureArray hash(const QCString &cs);

		/**
		 * %Hash a byte array, returning it as a printable
		 * string
		 * 
		 * This is a convenience method that returns the
		 * hash of a QSeecureArray as a hexadecimal
		 * representation encoded in a QString.
		 * 
		 * \param array the QByteArray to hash
		 *
		 * If you need more flexibility, you can create a Hash
		 * sub-class object, call Hash::update() as
		 * required, then call Hash::final(), before using
		 * the static arrayToHex() method.
		 */
		QString hashToString(const QSecureArray &array);

		/**
		 * \overload
		 *
		 * \param cs the QCString to hash		 
		 */
		QString hashToString(const QCString &cs);

	protected:
		/**
		 *  Constructor to override in sub-classes.
		 *
		 * \param type label for the type of hash to be
		 * implemented (eg "sha1" or "md2")
		 * \param provider the name of the provider plugin
		 * for the subclass (eg "qca-openssl")
		 */
		Hash(const QString &type, const QString &provider);
	};

	class QCA_EXPORT Cipher : public Algorithm, public Filter
	{
	public:
		/**
		* Mode settings for cipher algorithms
		 */
		enum Mode
		{
			CBC, /**< operate in %Cipher Block Chaining mode */
			CFB  /**< operate in %Cipher FeedBack mode */
		};

		Cipher(const Cipher &from);
		~Cipher();
		Cipher & operator=(const Cipher &from);

		KeyLength keyLength() const;
		bool validKeyLength(int n) const;

		int blockSize() const;

		virtual void clear();
		virtual QSecureArray update(const QSecureArray &a);
		virtual QSecureArray final();
		virtual bool ok() const;

		void setup(Mode m, Direction dir, const SymmetricKey &key, const InitializationVector &iv=InitializationVector(), bool pad = true);

	protected:
		Cipher(const QString &type, Mode m, Direction dir, const SymmetricKey &key, const InitializationVector &iv, bool pad, const QString &provider);

	private:
		class Private;
		Private *d;
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

		static QString withAlgorithm(const QString &macType, const QString &algType);

	protected:
		MessageAuthenticationCode(const QString &type, const SymmetricKey &key, const QString &provider);

	private:
		class Private;
		Private *d;
	};

	/**
	 * SHA-0 cryptographic message digest hash algorithm.
	 *
	 * %SHA0 is a 160 bit hashing function, no longer recommended
	 * for new applications because of known (partial) attacks
	 * against it.
	 *
	 * You can use this class in two basic ways - standard member
	 * methods, and convenience methods. Both are shown in
	 * the example below.
	 *
	 * \code
	 *        if(!QCA::isSupported("sha0"))
	 *                printf("SHA0 not supported!\n");
	 *        else {
	 *                QCString actualResult;
	 *                actualResult = QCA::SHA0().hashToString(message);
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
	 */
	class QCA_EXPORT SHA0 : public Hash
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a SHA-0 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using QCA::SHA0().hash()
		 *
		 * \param provider specify a particular provider 
		 * to use. For example if you wanted the SHA0 implementation
		 * from qca-openssl, you would use SHA0("qca-openssl")
		 */
		SHA0(const QString &provider = "") : Hash("sha0", provider) {}
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
	 * methods, and convenience methods. Both are shown in
	 * the example below.
	 *
	 * \code
	 *        if(!QCA::isSupported("sha1"))
	 *                printf("SHA1 not supported!\n");
	 *        else {
	 *                QCString actualResult;
	 *                actualResult = QCA::SHA1().hashToString(message);
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
	class QCA_EXPORT SHA1 : public Hash
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a SHA-1 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using QCA::SHA1().hash()
		 *
		 * \param provider specify a particular provider 
		 * to use. For example if you wanted the SHA1 implementation
		 * from qca-openssl, you would use SHA1("qca-openssl")
		 */
		SHA1(const QString &provider = "") : Hash("sha1", provider) {}
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
	class QCA_EXPORT SHA256 : public Hash
	{
	public:
		SHA256(const QString &provider = "") : Hash("sha256", provider) {}
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
	class QCA_EXPORT MD2 : public Hash
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating an MD-2 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using QCA::MD2().hash()
		 *
		 * \param provider specify a particular provider 
		 * to use. For example if you wanted the MD2 implementation
		 * from qca-openssl, you would use MD2("qca-openssl")
		 */
		MD2(const QString &provider = "") : Hash("md2", provider) {}
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
	class QCA_EXPORT MD4 : public Hash
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating an MD-4 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using QCA::MD4().hash()
		 *
		 * \param provider specify a particular provider 
		 * to use. For example if you wanted the MD4 implementation
		 * from qca-openssl, you would use MD4("qca-openssl")
		 */
		MD4(const QString &provider = "") : Hash("md4", provider) {}
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
	class QCA_EXPORT MD5 : public Hash
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating an MD-5 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using QCA::MD5().hash()
		 *
		 * \param provider specify a particular provider 
		 * to use. For example if you wanted the MD5 implementation
		 * from qca-openssl, you would use MD5("qca-openssl")
		 */
		MD5(const QString &provider = "") : Hash("md5", provider) {}
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
	 * methods, and convenience methods. Both are shown in
	 * the example below.
	 *
	 * \code
	 *        if(!QCA::isSupported("ripemd160")
	 *                printf("RIPEMD-160 not supported!\n");
	 *        else {
	 *                QCString actualResult;
	 *                actualResult = QCA::RIPEMD160().hashToString(message);
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
	class QCA_EXPORT RIPEMD160 : public Hash
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a RIPEMD160 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using
		 * QCA::RIPEMD160().hash()
		 *
		 * \param provider specify a particular provider 
		 * to use. For example if you wanted the RIPEMD160
		 * implementation from qca-openssl, you would use 
		 * RIPEMD160("qca-openssl")
		 */
		RIPEMD160(const QString &provider = "") : Hash("ripemd160", provider) {}
	};

	class QCA_EXPORT BlowFish : public Cipher
	{
	public:
		BlowFish(Mode m = CBC, Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), const InitializationVector &iv = InitializationVector(), bool pad = true, const QString &provider = "")
		:Cipher("blowfish", m, dir, key, iv, pad, provider) {}
	};

	class QCA_EXPORT TripleDES : public Cipher
	{
	public:
		TripleDES(Mode m = CBC, Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), const InitializationVector &iv = InitializationVector(), bool pad = true, const QString &provider = "")
		:Cipher("tripledes", m, dir, key, iv, pad, provider) {}
	};

	class QCA_EXPORT AES128 : public Cipher
	{
	public:
		AES128(Mode m = CBC, Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), const InitializationVector &iv = InitializationVector(), bool pad = true, const QString &provider = "")
		:Cipher("aes128", m, dir, key, iv, pad, provider) {}
	};

	class QCA_EXPORT AES256 : public Cipher
	{
	public:
		AES256(Mode m = CBC, Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), const InitializationVector &iv = InitializationVector(), bool pad = true, const QString &provider = "")
		:Cipher("aes256", m, dir, key, iv, pad, provider) {}
	};

	class QCA_EXPORT HMAC : public MessageAuthenticationCode
	{
	public:
		HMAC(const QString &hash = "sha1", const SymmetricKey &key = SymmetricKey(), const QString &provider = "") : MessageAuthenticationCode(withAlgorithm("hmac", hash), key, provider) {}
	};

	class PublicKey;
	class PrivateKey;
	class KeyGenerator;
	class RSAPublicKey;
	class RSAPrivateKey;
	class DSAPublicKey;
	class DSAPrivateKey;
	class DHPublicKey;
	class DHPrivateKey;
	class Certificate;

	class QCA_EXPORT PKey : public Algorithm
	{
	public:
		enum Type { RSA, DSA, DH };

		PKey();
		PKey(const PKey &from);
		~PKey();

		PKey & operator=(const PKey &from);

		bool isNull() const;
		Type type() const;

		bool isRSA() const;
		bool isDSA() const;
		bool isDH() const;

		bool isPublic() const;
		bool isPrivate() const;

		bool canKeyAgree() const;

		PublicKey toPublicKey() const;
		PrivateKey toPrivateKey() const;

		friend class KeyGenerator;

	protected:
		PKey(const QString &type, const QString &provider);
		void set(const PKey &k);

		RSAPublicKey toRSAPublicKey() const;
		RSAPrivateKey toRSAPrivateKey() const;
		DSAPublicKey toDSAPublicKey() const;
		DSAPrivateKey toDSAPrivateKey() const;
		DHPublicKey toDHPublicKey() const;
		DHPrivateKey toDHPrivateKey() const;

	private:
		class Private;
		Private *d;
	};

	class QCA_EXPORT PublicKey : public PKey
	{
	public:
		PublicKey();
		PublicKey(const PrivateKey &k);

		RSAPublicKey toRSA() const;
		DSAPublicKey toDSA() const;
		DHPublicKey toDH() const;

		bool canEncrypt() const;
		bool canVerify() const;

		// encrypt / verify
		int maximumEncryptSize() const;
		QSecureArray encrypt(const QSecureArray &a);
		void startVerify();
		void update(const QSecureArray &);
		bool validSignature(const QSecureArray &sig);
		bool verifyMessage(const QSecureArray &a, const QSecureArray &sig);

		// import / export
		QSecureArray toDER() const;
		QString toPEM() const;
		static PublicKey fromDER(const QSecureArray &a, const QString &provider = "");
		static PublicKey fromPEM(const QString &s, const QString &provider = "");

	protected:
		PublicKey(const QString &type, const QString &provider);

	private:
		friend class PrivateKey;
		friend class Certificate;
	};

	class QCA_EXPORT PrivateKey : public PKey
	{
	public:
		PrivateKey();

		RSAPrivateKey toRSA() const;
		DSAPrivateKey toDSA() const;
		DHPrivateKey toDH() const;

		bool canDecrypt() const;
		bool canSign() const;

		// decrypt / sign / key agreement
		bool decrypt(const QSecureArray &in, QSecureArray *out);
		void startSign();
		void update(const QSecureArray &);
		QSecureArray signature();
		QSecureArray signMessage(const QSecureArray &a);
		SymmetricKey deriveKey(const PublicKey &theirs);

		// import / export
		QSecureArray toDER(const QString &passphrase = "") const;
		QString toPEM(const QString &passphrase = "") const;
		static PrivateKey fromDER(const QSecureArray &a, const QString &passphrase = "", const QString &provider = "");
		static PrivateKey fromPEM(const QString &s, const QString &passphrase = "", const QString &provider = "");

	protected:
		PrivateKey(const QString &type, const QString &provider);
	};

	class QCA_EXPORT KeyGenerator : public QObject
	{
		Q_OBJECT
	public:
		KeyGenerator(QObject *parent = 0, const char *name = 0);
		~KeyGenerator();

		bool blocking() const;
		void setBlocking(bool b);
		bool isBusy() const;

		void generateRSA(int bits, int exp = 65537, const QString &provider = "");
		void generateDSA(DL_Group group, const QString &provider = "");
		void generateDH(DL_Group group, const QString &provider = "");
		PrivateKey result() const;

	signals:
		void finished();

	private:
		void done();

		class Private;
		Private *d;
	};

	class QCA_EXPORT RSAPublicKey : public PublicKey
	{
	public:
		RSAPublicKey();
		RSAPublicKey(const QBigInteger &n, const QBigInteger &e, const QString &provider = "");
		RSAPublicKey(const RSAPrivateKey &k);

		QBigInteger n() const;
		QBigInteger e() const;
	};

	class QCA_EXPORT RSAPrivateKey : public PrivateKey
	{
	public:
		RSAPrivateKey();
		RSAPrivateKey(const QBigInteger &p, const QBigInteger &q, const QBigInteger &d, const QBigInteger &n, const QBigInteger &e, const QString &provider = "");

		QBigInteger p() const;
		QBigInteger q() const;
		QBigInteger d() const;
		QBigInteger n() const;
		QBigInteger e() const;
	};

	class QCA_EXPORT DSAPublicKey : public PublicKey
	{
	public:
		DSAPublicKey();
		DSAPublicKey(DL_Group group, const QBigInteger &y, const QString &provider = "");
		DSAPublicKey(const DSAPrivateKey &k);

		DL_Group domain() const;
		QBigInteger y() const;
	};

	class QCA_EXPORT DSAPrivateKey : public PrivateKey
	{
	public:
		DSAPrivateKey();
		DSAPrivateKey(DL_Group group, const QBigInteger &x, const QBigInteger &y, const QString &provider = "");

		DL_Group domain() const;
		QBigInteger x() const;
		QBigInteger y() const;
	};

	class QCA_EXPORT DHPublicKey : public PublicKey
	{
	public:
		DHPublicKey();
		DHPublicKey(DL_Group group, const QBigInteger &y, const QString &provider = "");
		DHPublicKey(const DHPrivateKey &k);

		DL_Group domain() const;
		QBigInteger y() const;
	};

	class QCA_EXPORT DHPrivateKey : public PrivateKey
	{
	public:
		DHPrivateKey();
		DHPrivateKey(DL_Group group, const QBigInteger &x, const QBigInteger &y, const QString &provider = "");

		DL_Group domain() const;
		QBigInteger x() const;
		QBigInteger y() const;
	};

	class Store;

	class QCA_EXPORT Certificate : public Algorithm
	{
	public:
		typedef QMap<QString, QString> Info;

		Certificate();

		bool isNull() const;

		int version() const;
		QDateTime notValidBefore() const;
		QDateTime notValidAfter() const;

		Info subjectInfo() const;
		Info issuerInfo() const;

		QString commonName() const;
		QBigInteger serialNumber() const;
		PublicKey subjectPublicKey() const;

		// import / export
		QSecureArray toDER() const;
		QString toPEM() const;
		static Certificate fromDER(const QSecureArray &a, const QString &provider = "");
		static Certificate fromPEM(const QString &s, const QString &provider = "");

		bool matchesHostname(const QString &host) const;

	private:
		friend class Store;
	};

	class QCA_EXPORT CRL : public Algorithm
	{
	public:
		CRL();

		bool isNull() const;

		// import / export
		QSecureArray toDER() const;
		QString toPEM() const;
		static CRL fromDER(const QSecureArray &a, const QString &provider = "");
		static CRL fromPEM(const QString &s, const QString &provider = "");

	private:
		friend class Store;
	};

	class QCA_EXPORT Store : public Algorithm
	{
	public:
		Store(const QString &provider = "");

		void addCertificate(const Certificate &cert, bool trusted = false);
		void addCRL(const CRL &crl);
		CertValidity validate(const Certificate &cert, CertUsage u = Any) const;
	};

	// securefilter basic rule: after calling a function that might
	//  affect something, call others to get the results.
	//
	// write: call readOutgoing
	// writeIncoming: call status, read, and readOutgoing
	// close: call status and readOutgoing
	// status: if Closed, call readUnprocessed
	//
	class QCA_EXPORT SecureFilter
	{
	public:
		virtual ~SecureFilter();

		virtual bool isClosable() const;
		virtual bool haveClosed() const;
		virtual bool haveError() const = 0;
		virtual int bytesAvailable() const = 0;
		virtual int bytesOutgoingAvailable() const = 0;
		virtual void close();

		// plain (application side)
		virtual void write(const QSecureArray &a) = 0;
		virtual QSecureArray read() = 0;

		// encoded (network side)
		virtual void writeIncoming(const QByteArray &a) = 0;
		virtual QByteArray readOutgoing(int *plainBytes = 0) = 0;
		virtual QSecureArray readUnprocessed();
	};

	// securelayer - "nicer" interface, using signals.  subclass
	//  should call layerUpdate after write, writeIncoming, or close.
	class QCA_EXPORT SecureLayer : public QObject, public SecureFilter
	{
		Q_OBJECT
	public:
		SecureLayer(QObject *parent = 0, const char *name = 0);

	protected:
		void layerUpdateBegin();
		void layerUpdateEnd();

	signals:
		void readyRead();
		void readyReadOutgoing();
		void closed();
		void error();

	private:
		int _read, _readout;
		bool _closed, _error;
	};

	/*class QCA_EXPORT TLS : public SecureLayer, public Algorithm
	{
		Q_OBJECT
	public:
		enum IdentityResult { Valid, HostMismatch, BadCert, NoCert };
		enum Error { ErrHandshake, ErrCrypt };

		TLS(QObject *parent = 0, const char *name = 0, const QString &provider = "");
		~TLS();

		void reset();

		void setCertificate(const Certificate &cert, const PrivateKey &key);
		void setStore(Store *store); // note: must persist

		bool startClient(const QString &host = "");
		bool startServer();
		bool isHandshaken() const;
		Error errorCode() const;

		IdentityResult peerIdentityResult() const;
		CertValidity peerCertificateValidity() const;
		Certificate localCertificate() const;
		Certificate peerCertificate() const;

		// reimplemented
		virtual bool isClosable() const;
		virtual bool haveClosed() const;
		virtual bool haveError() const;
		virtual int bytesAvailable() const;
		virtual int bytesOutgoingAvailable() const;
		virtual void close();
		virtual void write(const QSecureArray &a);
		virtual QSecureArray read();
		virtual void writeIncoming(const QByteArray &a);
		virtual QByteArray readOutgoing();
		virtual QSecureArray readUnprocessed();

	signals:
		void handshaken();

	private:
		class Private;
		Private *d;
	};*/

#if 0
	//class QCA_EXPORT TLS : public QObject
	//{
		//Q_OBJECT
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

	//class QCA_EXPORT SASL : public QObject
	//{
		//Q_OBJECT
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
#endif
};

#endif
