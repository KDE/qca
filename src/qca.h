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

#define QCA_VERSION 0x020000

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
 *   - Secure byte arrays (QSecureArray)
 *   - Arbitrary precision integers (QBigInteger)
 *   - Random number generation (QCA::Random)
 *   - SSL/TLS (TBC)
 *   - X509 certificate (Cert) (TBC)
 *   - Simple Authentication and Security Layer (SASL) (TBC)
 *   - RSA (TBC)
 *   - Hashing 
 *       - QCA::SHA0
 *       - QCA::SHA1
 *       - QCA::MD2
 *       - QCA::MD4
 *       - QCA::MD5
 *       - QCA::RIPEMD160
 *       - QCA::SHA256
 *       - QCA::SHA384
 *       - QCA::SHA512
 *   - Ciphers
 *       - BlowFish  (QCA::BlowFish)
 *       - Triple DES (QCA::TripleDES)
 *       - AES (QCA::AES128, QCA::AES192, QCA::AES256)
 *   - Keyed Hash Message Authentication Code (QCA::HMAC)
 *       - QCA::SHA1
 *       - QCA::MD5
 *       - QCA::RIPEMD160
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
 * be held in pages that might be swapped to disk or free'd without being
 * cleared first.
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
	 * Construct a secure byte array from a string
	 *
	 * Note that this copies, rather than references the source array
	 *
	 * \sa operator=()
	 */
	QSecureArray(const QCString &cs);

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
	 * Creates a copy, rather than references
	 *
	 * \param cs the string to copy from
	 */
	QSecureArray & operator=(const QCString &cs);

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
	 * Pointer to the data in the secure array
	 * 
	 * You can use this for memcpy and similar functions. If you are trying
	 * to obtain data at a particular offset, you might be better off using
	 * at() or operator[]
	 *
	 */
	const char *data() const;

	/**
	 * Pointer to the data in the secure array
	 * 
	 * You can use this for memcpy and similar functions. If you are trying
	 * to obtain data at a particular offset, you might be better off using
	 * at() or operator[]
	 *
	 */
	char *data();

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
	 * Returns the number of bytes in the array
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

	/**
	 * Append a secure byte array to the end of this array
	 */
	QSecureArray & append(const QSecureArray &a);
protected:
	/**
	 * Assign the contents of a provided byte array to this
	 * object.
	 *
	 * \param from the byte array to copy
	 */
	void set(const QSecureArray &from);
	/**
	 * Assign the contents of a provided string to this
	 * object.
	 *
	 * \param cs the QCString to copy
	 */
	void set(const QCString &cs);

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
 * Inequality operator. Returns true if the two QSecureArray
 * arguments have different length, or the same lengh but
 * different data
 *
 * \relates QSecureArray
 **/
bool operator!=(const QSecureArray &a, const QSecureArray &b);

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

	/**
	 * Convenience representation for the plugin providers
	 * 
	 * You can get a list of providers using the providers()
	 * function
	 *
	 * \sa ProviderListIterator
	 * \sa providers()
	 */
	typedef QPtrList<Provider> ProviderList;

	/**
	 * Convenience representation for iterator for the plugin providers
	 *
	 * You would use this something like the following:
	 * \code
	 * QCA::ProviderList qcaProviders = QCA::providers();
	 * QCA::ProviderListIterator it( qcaProviders );
	 * QCA::Provider *provider;
	 * while ( 0 != (provider = it.current() ) ) {
	 *     ++it;
	 *     cout << provider->name();
	 * }
	 * \endcode
	 *
	 * \sa ProviderList
	 * \sa providers()
	 */
	typedef QPtrListIterator<Provider> ProviderListIterator;

	/**
	 * Mode settings for memory allocation
	 *
	 * QCA can use secure memory, however most operating systems
	 * restrict the amount of memory that can be pinned by user
	 * applications, to prevent a denial-of-service attack. 
	 *
	 * QCA supports two approaches to getting memory - the mlock
	 * method, which generally requires root (administrator) level
	 * privileges, and the mmap method which is not as secure, but
	 * which should be able to be used by any process.
	 * 
	 * \sa Initializer
	 */
	enum MemoryMode
	{
		Practical, ///< mlock and drop root if available, else mmap
		Locking, ///< mlock and drop root
		LockingKeepPrivileges ///< mlock, retaining root privileges
	};

	/**
	 * Direction settings for symmetric algorithms
	 *
	 * For some algorithms, it makes sense to have a "direction", such
	 * as Cipher algorithms which can be used to encrypt or decrypt.
	 */
	enum Direction
	{
		Encode, ///< Operate in the "forward" direction; for example, encrypting
		Decode  ///< Operate in the "reverse" direction; for example, decrypting
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

	/**
	 * Specify the lower-bound for acceptable TLS/SASL security layers
	 */
	enum SecurityLevel
	{
		SL_None,      ///< indicates that no security is ok
		SL_Integrity, ///< must at least get integrity protection
		SL_Export,    ///< must be export level bits or more
		SL_Baseline,  ///< must be 128 bit or more
		SL_High,      ///< must be more than 128 bit
		SL_Highest    ///< SL_High or max possible, whichever is greater
	};

	/**
	 * Initialise QCA
	 */
	QCA_EXPORT void init();
	/**
	 * \overload
	 *
	 * \param m the MemoryMode to use
	 * \param prealloc the amount of memory in kilobytes to allocate
	 *                 for secure storage
	 */
	QCA_EXPORT void init(MemoryMode m, int prealloc);

	QCA_EXPORT void deinit();
	/**
	 * Test if secure storage memory is available
	 *
	 * \return true if secure storage memory is available
	 */ 
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

	/**
	 * Return a list of the current providers
	 *
	 * The current plugin providers are provided as a list, which you
	 * can iterate over using ProviderListIterator.
	 *
	 * \sa ProviderList
	 * \sa ProviderListIterator
	 */
	QCA_EXPORT const ProviderList & providers();

	QCA_EXPORT void unloadAllPlugins();

	/**
	 * Return the Random provider that is currently set to be the
	 * global random number generator.
	 *
	 * For example, to get the name of the provider that is currently
	 * providing the Random capability, you could use:
	 * \code
	 * QCA::Random rng = QCA::globalRNG();
         * std::cout << "Provider name: " << rng.provider()->name() << std::endl;
	 * \endcode
	 */
	QCA_EXPORT Random & globalRNG();

	/**
	 * Change the global random generation provider
	 *
	 * The Random capabilities of %QCA are provided as part of the
	 * built in capabilities, however the generator can be changed
	 * if required.
	 */
	QCA_EXPORT void setGlobalRNG(const QString &provider);

	/**
	 * Get the application name that will be used by SASL server mode
	 *
	 * The application name is used by SASL in server mode, as some systems might
	 * have different security policies depending on the app.
	 * The default application name  is 'qca'
	 */
	QCA_EXPORT QString appName();

	/**
	 * Set the application name that will be used by SASL server mode
	 *
	 * The application name is used by SASL in server mode, as some systems might
	 * have different security policies depending on the app. This should be set 
	 * before using SASL objects, and it cannot be changed later.
	 *
	 * \param name the name string to use for SASL server mode
	 */
	QCA_EXPORT void setAppName(const QString &name);

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

	/**
	 * Simple container for acceptable key lengths
	 *
	 * The KeyLength specifies the minimum and maximum byte sizes
	 * allowed for a key, as well as a "multiple" which the key
	 * size must evenly divide into.
	 * 
	 * As an example, if the key can be 4, 8 or 12 bytes, you can
	 * express this as 
	 * \code
	 * KeyLength keyLen( 4, 12, 4 );
	 * \endcode
	 * 
	 * If you want to express a KeyLength that takes any number
	 * of bytes (including zero), you may want to use
	 * \code
	 * #include<limits>
	 * KeyLength( 0, std::numeric_limits<int>::max(), 1 );
	 * \endcode
	 */
	class QCA_EXPORT KeyLength
	{
	public:
		/**
		 * Construct a %KeyLength object
		 *
		 * \param min the minimum length of the key, in bytes
		 * \param max the maximum length of the key, in bytes
		 * \param multiple the number of bytes that the key must be a 
		 * multiple of.
		 */
		KeyLength(int min, int max, int multiple)
			: _min( min ), _max(max), _multiple( multiple )
		{ }
		/**
		 * Obtain the minimum length for the key, in bytes
		 */
		int minimum() const { return _min; }

		/**
		 * Obtain the maximum length for the key, in bytes
		 */
		int maximum() const { return _max; }

		/**
		 * Return the number of bytes that the key must be a multiple of
		 *
		 * If this is one, then anything between minumum and maximum (inclusive)
		 * is acceptable.
		 */
		int multiple() const { return _multiple; }

	private:
		int const _min, _max, _multiple;
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

	protected:
		Algorithm();
		Algorithm(const QString &type, const QString &provider);
		Provider::Context *context() const;
		void change(Provider::Context *c);
		void change(const QString &type, const QString &provider);
		void detach();

	private:
		class Private;
		Private *d;
	};

	/**
	 * Source of random numbers
	 *
	 * QCA provides a built in source of random numbers, which
	 * can be accessed through this class. You can also use
	 * an alternative random number source, by implementing
	 * another provider.
	 *
	 * You can select the "quality" of the random numbers. For 
	 * best results, you should use Nonce or PublicValue for values
	 * that are likely to become public, and SessionKey or LongTermKey
	 * for those values that are more critical. All that said, please
	 * note that this is only a hint to the provider - it may make
	 * no difference at all.
	 *
	 * The normal use of this class is expected to be through the
	 * static members - randomChar(), randomInt() and randomArray().
	 */
	class QCA_EXPORT Random : public Algorithm
	{
	public:
		/**
		 * How much entropy to use for the random numbers that
		 * are required.
		 */
		enum Quality { Nonce, PublicValue, SessionKey, LongTermKey };

		/**
		 * Standard Constructor
		 *
		 * \param provider the provider library for the random
		 *                 number generation
		 */ 
		Random(const QString &provider = "");

		/**
		 * Provide a random byte.
		 *
		 * This method isn't normally required - you should use
		 * the static randomChar() method instead.
		 * 
		 * \param q the quality of the random byte that is required
		 *
		 * \sa randomChar
		 */
		uchar nextByte(Quality q = SessionKey);

		/**
		 * Provide a specified number of random bytes
		 *
		 * This method isn't normally required - you should use
		 * the static randomArray() method instead.
		 *
		 * \param size the number of bytes to provide
		 * \param q the quality of the random bytes that are required
		 *
		 * \sa randomArray
		 */
		QSecureArray nextBytes(int size, Quality q = SessionKey);

		/**
		 * Provide a random character (byte)
		 *
		 * This is the normal way of obtaining a single random char
		 * (ie. 8 bit byte), of the default quality, as shown below:
		 * \code
		 * myRandomChar = QCA::Random::randomChar();
		 * \endcode
		 * 
		 * \param q the quality of the random character that is required
		 *
		 * If you need a number of bytes, perhaps randomArray() may be of use
		 */
		static uchar randomChar(Quality q = SessionKey);

		/**
		 * Provide a random integer
		 *
		 * This is the normal way of obtaining a single random integer,
		 * as shown below:
		 * \code
		 * // default quality
		 * myRandomInt = QCA::Random::randomInt();
		 * // cheap integer
		 * myCheapInt = QCA::Random::randomInt( QCA::Random::Nonce );
		 * \endcode
		 *
		 * \param q the quality of the random integer that is required
		 */
		static uint randomInt(Quality q = SessionKey);

		/**
		 * Provide a specified number of random bytes
		 * 
		 * \code
		 * // build a 30 byte secure array.
		 * QSecureArray arry = QCA::Random::randomArray(30);
		 * // take 20 bytes, as high a quality as we can get
		 * QSecureArray newKey = QCA::Random::randomArray(20, QCA::Random::LongTermKey);
		 * \endcode
		 *
		 * \param size the number of bytes to provide
		 * \param q the quality of the random bytes that are required
		 */
		static QSecureArray randomArray(int size, Quality q = SessionKey);
	};

	/**
	 * Container for keys for symmetric encryption algorithms.
	 */
	class QCA_EXPORT SymmetricKey : public QSecureArray
	{
	public:
		/**
		 * Construct an empty (zero length) key
		 */
		SymmetricKey();

		/**
		 * Construct an key of specified size, with random contents
		 *
		 * This is intended to be used as a random session key.
		 *
		 * \param size the number of bytes for the key
		 *
		 */
		SymmetricKey(int size);

		/**
		 * Construct a key from a provided byte array
		 *
		 * \param a the byte array to copy
		 */
		SymmetricKey(const QSecureArray &a);

		/**
		 * Construct a key from a provided string
		 *
		 * \param cs the QCString to copy
		 */
		SymmetricKey(const QCString &cs);
	};

	class QCA_EXPORT InitializationVector : public QSecureArray
	{
	public:
		InitializationVector();
		InitializationVector(int size);
		InitializationVector(const QSecureArray &a);
		InitializationVector(const QCString &cs);
	};

	/**
	 * General superclass for hashing algorithms.
	 *
	 * %Hash is a superclass for the various hashing algorithms
	 * within %QCA. You should not need to use it directly unless you are
	 * adding another hashing capability to %QCA - you should be
	 * using a sub-class. SHA1 or RIPEMD160 are recommended for
	 * new applications, although MD2, MD4, MD5 or SHA0 may be
	 * applicable (for interoperability reasons) for some
	 * applications. 
	 *
	 * To perform a hash, you create an object (of one of the
	 * sub-classes of %Hash), call update() with the data that
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
 		 * \param a the byte array to add to the hash 
		 */
		virtual void update(const QSecureArray &a);

		/**
		 * \overload
		 *
		 * \param a the QByteArray to add to the hash 
		 */
		virtual void update(const QByteArray &a);

		/**
		 * \overload
		 *
		 * This method is provided to assist with code that
		 * already exists, and is being ported to %QCA. You are
		 * better off passing a QSecureArray (as shown above)
		 * if you are writing new code.
		 *
		 * \param data pointer to a char array
		 * \param len the length of the array. If not specified
		 * (or specified as a negative number), the length will be
		 * determined with strlen(), which may not be what you want
		 * if the array contains a null (0x00) character.
		 */
		virtual void update(const char *data, int len = -1);

		/**
		 * \overload
		 *
		 * This allows you to read from a file or other
		 * I/O device. Note that the device must be already
		 * open for reading
		 *
		 * \param file an I/O device
		 *
		 * If you are trying to calculate the hash of
		 * a whole file (and it isn't already open), you
		 * might want to use code like this:
		 * \code
		 * QFile f( "file.dat" );
		 * if ( f1.open( IO_ReadOnly ) ) {
		 *     QCA::SHA1 hashObj;
		 *     hashObj.update( f1 );
		 *     QString output = hashObj.final() ) ),
		 * }
		 * \endcode
		 */
		virtual void update(QIODevice &file);

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

	/**
	 * General superclass for cipher (encryption / decryption) algorithms.
	 *
	 * %Cipher is a superclass for the various algorithms that perform
	 * low level encryption and decryption within %QCA. You should
	 * not need to use it directly unless you are
	 * adding another capability to %QCA - you should be
	 * using a sub-class. AES is recommended for new applications.
	 */
	class QCA_EXPORT Cipher : public Algorithm, public Filter
	{
	public:
		/**
		 * Mode settings for cipher algorithms
		 */
		enum Mode
		{
			CBC, ///< operate in %Cipher Block Chaining mode
			CFB, ///< operate in %Cipher FeedBack mode
			ECB  ///< operate in Electronic Code Book mode
		};

		/** 
		 * Standard copy constructor
		 */
		Cipher(const Cipher &from);
		~Cipher();

		Cipher & operator=(const Cipher &from);

		/**
		 * Return acceptable key lengths
		 */
		KeyLength keyLength() const;

		/**
		 * Test if a key length is valid for the cipher algorithm
		 *
		 * \param n the key length in bytes
		 * \return true if the key would be valid for the current algorithm
		 */
		bool validKeyLength(int n) const;

		/**
		 * return the block size for the cipher object
		 */
		int blockSize() const;

		/**
		 * reset the cipher object, to allow re-use
		 */
		virtual void clear();

		/** 
		 * pass in a byte array of data, which will be encrypted or decrypted
		 * (according to the Direction that was set in the constructor or in
		 * setup() ) and returned.
		 *
		 * \param a the array of data to encrypt / decrypt
		 */
		virtual QSecureArray update(const QSecureArray &a);

		/**
		 * complete the block of data, padding as required, and returning
		 * the completed block
		 */
		virtual QSecureArray final();

		virtual bool ok() const;

		// note: padding only applies to CBC and ECB.  CFB ciphertext is
		//   always the length of the plaintext.
		void setup(Mode m, Direction dir, const SymmetricKey &key, const InitializationVector &iv = InitializationVector(), bool pad = true);

	protected:
		Cipher(const QString &type, Mode m, Direction dir, const SymmetricKey &key, const InitializationVector &iv, bool pad, const QString &provider);

	private:
		class Private;
		Private *d;
	};

	/**
	 * General superclass for message authentication code (MAC) algorithms.
	 *
	 * %MessageAuthenticationCode is a superclass for the various 
	 * message authentication code algorithms within %QCA. You should
	 * not need to use it directly unless you are
	 * adding another message authentication code capability to %QCA - you should be
	 * using a sub-class. HMAC using SHA1 is recommended for new applications.
	 */
	class QCA_EXPORT MessageAuthenticationCode : public Algorithm, public BufferedComputation
	{
	public:
		/**
		 * Standard copy constructor
		 */
		MessageAuthenticationCode(const MessageAuthenticationCode &from);

		~MessageAuthenticationCode();

		/**
		 * Assignment operator.
		 *
		 * Copies the state (including key) from one MessageAuthenticationCode
		 * to another
		 */
		MessageAuthenticationCode & operator=(const MessageAuthenticationCode &from);

		/**
		 * Return acceptable key lengths
		 */
		KeyLength keyLength() const;

		/**
		 * Test if a key length is valid for the MAC algorithm
		 *
		 * \param n the key length in bytes
		 * \return true if the key would be valid for the current algorithm
		 */
		bool validKeyLength(int n) const;
		
		/**
		 * Reset a MessageAuthenticationCode, dumping all
		 * previous parts of the message.
		 *
		 * This method clears (or resets) the algorithm,
		 * effectively undoing any previous update()
		 * calls. You should use this call if you are re-using
		 * a %MessageAuthenticationCode sub-class object
		 * to calculate additional MACs. Note that if the key
		 * doesn't need to be changed, you don't need to call
		 * setup() again, since the key can just be reused.
		 */
		virtual void clear();

		/**
		 * Update the MAC, adding more of the message contents
		 * to the digest. The whole message needs to be added
		 * using this method before you call final(). 
		 *
		 * \param array the message contents
		 */
		virtual void update(const QSecureArray &array);

		/**
		 * Finalises input and returns the MAC result
		 *
		 * After calling update() with the required data, the
		 * hash results are finalised and produced.
		 *
		 * Note that it is not possible to add further data (with
		 * update()) after calling final(). If you want to
		 * reuse the %MessageAuthenticationCode object, you
		 * should call clear() and start to update() again.
		 */
		virtual QSecureArray final();

		/**
		 * Initialise the MAC algorithm.
		 *
		 * \param key the key to use for the algorithm
		 */
		void setup(const SymmetricKey &key);

		/**
		 * Construct the name of the algorithm
		 *
		 * You can use this to build a standard name string.
		 * You probably only need this method if you are 
		 * creating a new subclass.
		 */
		static QString withAlgorithm(const QString &macType, const QString &algType);

	protected:
		/**
		 * Special constructor for subclass initialisation
		 *
		 * To create HMAC with a default algorithm of "sha1", you would use something like:
		 * \code
		 * HMAC(const QString &hash = "sha1", const SymmetricKey &key = SymmetricKey(), const QString &provider = "")
		 * : MessageAuthenticationCode(withAlgorithm("hmac", hash), key, provider)
		 * {
		 * }
		 * \endcode
		 *
		 * \note The HMAC subclass is already provided in QCA - you don't need to create
		 * your own.
		 */
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
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a SHA256 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using
		 * QCA::SHA256().hash()
		 *
		 * \param provider specify a particular provider 
		 * to use. For example if you wanted the SHA256 implementation
		 * from qca-gcrypt, you would use SHA256("qca-gcrypt")
		 */
		SHA256(const QString &provider = "") : Hash("sha256", provider) {}
	};

	/**
	 * SHA-384 cryptographic message digest hash algorithm.
	 *
	 * This algorithm takes an arbitrary data stream, known as the
	 * message (up to \f$2^{128}\f$ bits in length) and outputs a
	 * condensed 384 bit (48 byte) representation of that data
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
	class QCA_EXPORT SHA384 : public Hash
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a SHA384 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using
		 * QCA::SHA384().hash()
		 *
		 * \param provider specify a particular provider 
		 * to use. For example if you wanted the SHA384 implementation
		 * from qca-gcrypt, you would use SHA384("qca-gcrypt")
		 */
		SHA384(const QString &provider = "") : Hash("sha384", provider) {}
	};

	/**
	 * SHA-512 cryptographic message digest hash algorithm.
	 *
	 * This algorithm takes an arbitrary data stream, known as the
	 * message (up to \f$2^{128}\f$ bits in length) and outputs a
	 * condensed 512 bit (64 byte) representation of that data
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
	class QCA_EXPORT SHA512 : public Hash
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a SHA512 hash,
		 * although if you have the whole message in memory at
		 * one time, you may be better off using
		 * QCA::SHA512().hash()
		 *
		 * \param provider specify a particular provider 
		 * to use. For example if you wanted the SHA512 implementation
		 * from qca-gcrypt, you would use SHA512("qca-gcrypt")
		 */
		SHA512(const QString &provider = "") : Hash("sha512", provider) {}
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

	/**
	 * Bruce Schneier Blowfish %Cipher
	 *
	 */
	class QCA_EXPORT BlowFish : public Cipher
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a %BlowFish encryption or decryption object.
		 *
		 * \param m the Mode to operate in
		 * \param dir whether this object should encrypt (QCA::Encode) or decypt (QCA::Decode)
		 * \param key the key to use. 
		 * \param iv the initialisation vector to use. Ignored for ECB mode.
		 * \param pad whether to apply padding, or not.
		 * \param provider the provider to use (eg "qca-gcrypt" )
		 *
		 */
		BlowFish(Mode m = CBC, Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), const InitializationVector &iv = InitializationVector(), bool pad = true, const QString &provider = "")
		:Cipher("blowfish", m, dir, key, iv, pad, provider) {}
	};

	/**
	 * Triple DES %Cipher
	 *
	 */
	class QCA_EXPORT TripleDES : public Cipher
	{
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a triple DES encryption or decryption object.
		 *
		 * \param m the Mode to operate in
		 * \param dir whether this object should encrypt (QCA::Encode) or decypt (QCA::Decode)
		 * \param key the key to use. Note that triple DES requires a 24 byte (192 bit) key,
		 * even though the effective key length is 168 bits.
		 * \param iv the initialisation vector to use. Ignored for ECB mode.
		 * \param pad whether to apply padding, or not.
		 * \param provider the provider to use (eg "qca-gcrypt" )
		 *
		 */
	public:
		TripleDES(Mode m = CBC, Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), const InitializationVector &iv = InitializationVector(), bool pad = true, const QString &provider = "")
		:Cipher("tripledes", m, dir, key, iv, pad, provider) {}
	};

	/**
	 * Advanced Encryption Standard %Cipher - 128 bits
	 *
	 */
	class QCA_EXPORT AES128 : public Cipher
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a 128 bit 
		 * AES encryption or decryption object.
		 *
		 * \param m the Mode to operate in
		 * \param dir whether this object should encrypt (QCA::Encode) or decypt (QCA::Decode)
		 * \param key the key to use. Note that AES128 requires a 16 byte (128 bit) key.
		 * \param iv the initialisation vector to use. Ignored for ECB mode.
		 * \param pad whether to apply padding, or not.
		 * \param provider the provider to use (eg "qca-gcrypt" )
		 *
		 */
		AES128(Mode m = CBC, Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), const InitializationVector &iv = InitializationVector(), bool pad = true, const QString &provider = "")
		:Cipher("aes128", m, dir, key, iv, pad, provider) {}
	};

	/**
	 * Advanced Encryption Standard %Cipher - 192 bits
	 *
	 */
	class QCA_EXPORT AES192 : public Cipher
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a 192 bit 
		 * AES encryption or decryption object.
		 *
		 * \param m the Mode to operate in
		 * \param dir whether this object should encrypt (QCA::Encode) or decypt (QCA::Decode)
		 * \param key the key to use. Note that AES192 requires a 24 byte (192 bit) key.
		 * \param iv the initialisation vector to use. Ignored for ECB mode.
		 * \param pad whether to apply padding, or not.
		 * \param provider the provider to use (eg "qca-gcrypt" )
		 *
		 */
		AES192(Mode m = CBC, Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), const InitializationVector &iv = InitializationVector(), bool pad = true, const QString &provider = "")
		:Cipher("aes192", m, dir, key, iv, pad, provider) {}
	};

	/**
	 * Advanced Encryption Standard %Cipher - 256 bits
	 *
	 */
	class QCA_EXPORT AES256 : public Cipher
	{
	public:
		/**
		 * Standard constructor
		 *
		 * This is the normal way of creating a 256 bit 
		 * AES encryption or decryption object.
		 *
		 * \param m the Mode to operate in
		 * \param dir whether this object should encrypt (QCA::Encode) or decypt (QCA::Decode)
		 * \param key the key to use. Note that AES256 requires a 32 byte (256 bit) key.
		 * \param iv the initialisation vector to use. Ignored for ECB mode.
		 * \param pad whether to apply padding, or not.
		 * \param provider the provider to use (eg "qca-gcrypt" )
		 *
		 */
		AES256(Mode m = CBC, Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), const InitializationVector &iv = InitializationVector(), bool pad = true, const QString &provider = "")
		:Cipher("aes256", m, dir, key, iv, pad, provider) {}
	};


	/**
	 * Keyed %Hash message authentication codes
	 *
	 * This algorithm takes an arbitrary data stream, known as the
	 * message and outputs an authentication code for that message.
	 * The authentication code is generated using a secret key in
	 * such a way that the authentication code shows that the 
	 * message has not be altered.
	 *
	 * As an example, to create a MAC using HMAC with SHA1, you
	 * could do the following:
	 * \code
	 * if( QCA::isSupported( "hmac(sha1)" ) ) {
	 *      QCA::HMAC hmacObj; // don't need to specify, "sha1" is default
	 *	hmacObj.setup( key ); // key is a QCA::SymmetricKey, set elsewhere
	 *                            // could also be done in constructor
	 *    	hmacObj.update( dataArray ); // dataArray is a QSecureArray, set elsewhere
	 *	output = hmacObj.final();
	 * }
	 * \endcode
	 *
	 * Note that if your application is potentially susceptable to "replay attacks"
	 * where the message is sent more than once, you should include a counter in
	 * the message that is covered by the MAC, and check that the counter is always
	 * incremented every time you recieve a message and MAC.
	 *
	 * For more information, see H. Krawczyk et al. RFC2104 
	 * "HMAC: Keyed-Hashing for Message Authentication"
	 */
	class QCA_EXPORT HMAC : public MessageAuthenticationCode
	{
	public:
		/**
		 * %HMAC constructor
		 *
		 * To create a simple HMAC object
		 * \param hash the type of the hash (eg "sha1", "md5" or "ripemd160" )
		 * \param key the key to use for the HMAC algorithm.
		 * \param provider the name of the provider to use (eg "qca-openssl")
		 *
		 * To construct a keyed-hash message authentication code object, you
		 * can do one of the following variations.
		 * \code
		 * QCA::HMAC sha1HMAC; // defaults to SHA1
		 * QCA::HMAC sha1HMAC( "sha1" ); // explicitly SHA1, but same as above
		 * QCA::HMAC md5HMAC( "md5" );  // MD5 algorithm
		 * QCA::HMAC sha1HMAC( "sha1", key ); // key is a QCA::SymmetricKey
		 * // next line uses RIPEMD160, empty key, implementation from qca-openssl provider
		 * QCA::HMAC ripemd160HMAC( "ripemd160", QCA::SymmetricKey(), "qca-openssl" );
		 * \endcode
		 */
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
	class CRL;
	class Store;
	class TLS;

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

	private:
		friend class TLS;
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
		friend class TLS;
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

	private:
		friend class TLS;
	};

	// securefilter basic rule: after calling a function that might
	//  affect something, call others to get the results.
	//
	// write: call readOutgoing
	// writeIncoming: call haveClosed/haveError, read, and readOutgoing
	// close: call haveClosed/haveError and readOutgoing
	// haveClosed: if Closed, call readUnprocessed
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
	//  should call layerUpdateBegin/End before and after write,
	//  writeIncoming, or close.
	class QCA_EXPORT SecureLayer : public QObject, public SecureFilter
	{
		Q_OBJECT
	public:
		SecureLayer(QObject *parent = 0, const char *name = 0);

		void setStatefulOnly(bool b);

	protected:
		void layerUpdateBegin();
		void layerUpdateEnd();

	signals:
		void readyRead();
		void readyReadOutgoing();
		void closed();
		void error();

	private:
		bool _signals;
		int _read, _readout;
		bool _closed, _error;
	};

	class QCA_EXPORT TLS : public SecureLayer, public Algorithm
	{
		Q_OBJECT
	public:
		enum Error
		{
			ErrHandshake, ///< problem during the negotiation
			ErrCrypt      ///< problem at anytime after
		};
		enum IdentityResult
		{
			Valid,        ///< identity is verified
			HostMismatch, ///< valid cert provided, but wrong owner
			BadCert,      ///< invalid cert
			NoCert        ///< identity unknown
		};

		TLS(QObject *parent = 0, const char *name = 0, const QString &provider = "");
		~TLS();

		void reset();

		void setCertificate(const Certificate &cert, const PrivateKey &key);
		void setStore(const Store &store);
		void setConstraints(SecurityLevel s);
		void setConstraints(int minSSF, int maxSSF);
		void setCompressionEnabled(bool b); // only a 'hint'

		bool startClient(const QString &host = "");
		bool startServer();
		bool isHandshaken() const;
		QString cipherName() const;
		int cipherBits() const;
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
		virtual QByteArray readOutgoing(int *plainBytes = 0);
		virtual QSecureArray readUnprocessed();

	signals:
		void handshaken();

	public:
		class Private;
	private:
		friend class Private;
		Private *d;
	};

	class QCA_EXPORT SASL : public SecureLayer, public Algorithm
	{
		Q_OBJECT
	public:
		enum Error
		{
			ErrAuth, ///< problem during the authentication process
			ErrCrypt ///< problem at anytime after
		};
		enum AuthCondition
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
		enum AuthFlags
		{
			AllowPlain             = 0x01,
			AllowAnonymous         = 0x02,
			RequireForwardSecrecy  = 0x04,
			RequirePassCredentials = 0x08,
			RequireMutualAuth      = 0x10,
			RequireAuthzidSupport  = 0x20  // server-only
		};

		SASL(QObject *parent = 0, const char *name = 0, const QString &provider = "");
		~SASL();

		void reset();

		// configuration
		void setConstraints(AuthFlags f, SecurityLevel s = SL_None);
		void setConstraints(AuthFlags f, int minSSF, int maxSSF);
		void setLocalAddr(const QHostAddress &addr, Q_UINT16 port);
		void setRemoteAddr(const QHostAddress &addr, Q_UINT16 port);
		void setExternalAuthID(const QString &authid);
		void setExternalSSF(int);

		// main
		bool startClient(const QString &service, const QString &host, const QStringList &mechlist, bool allowClientSendFirst = true);
		bool startServer(const QString &service, const QString &host, const QString &realm, QStringList *mechlist, bool allowServerSendLast = false);
		void putStep(const QByteArray &stepData);
		void putServerFirstStep(const QString &mech);
		void putServerFirstStep(const QString &mech, const QByteArray &clientInit);
		int ssf() const;
		Error errorCode() const;
		AuthCondition authCondition() const;

		// authentication
		void setUsername(const QString &user);
		void setAuthzid(const QString &auth);
		void setPassword(const QSecureArray &pass);
		void setRealm(const QString &realm);
		void continueAfterParams();
		void continueAfterAuthCheck();

		// reimplemented
		virtual bool haveError() const;
		virtual int bytesAvailable() const;
		virtual int bytesOutgoingAvailable() const;
		virtual void close();
		virtual void write(const QSecureArray &a);
		virtual QSecureArray read();
		virtual void writeIncoming(const QByteArray &a);
		virtual QByteArray readOutgoing(int *plainBytes = 0);

	signals:
		void clientFirstStep(const QString &mech, const QByteArray *clientInit);
		void nextStep(const QByteArray &stepData);
		void needParams(bool user, bool authzid, bool pass, bool realm);
		void authCheck(const QString &user, const QString &authzid);
		void authenticated();

	public:
		class Private;
	private:
		friend class Private;
		Private *d;
	};
};

#endif
