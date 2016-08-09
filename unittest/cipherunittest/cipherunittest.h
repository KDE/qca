#ifndef CIPHERUNITTEST_H
#define CIPHERUNITTEST_H

#include <QtCrypto>

class CipherUnitTest : public QObject
{

	Q_OBJECT

private slots:
	void initTestCase();
	void cleanupTestCase();
	void aes128_data();
	void aes128();
	void aes128_cbc_data();
	void aes128_cbc();
	void aes128_cbc_pkcs7_data();
	void aes128_cbc_pkcs7();
	void aes128_cfb_data();
	void aes128_cfb();
	void aes128_ofb_data();
	void aes128_ofb();
	void aes128_ctr_data();
	void aes128_ctr();

	void aes192_data();
	void aes192();
	void aes192_cbc_data();
	void aes192_cbc();
	void aes192_cbc_pkcs7_data();
	void aes192_cbc_pkcs7();
	void aes192_cfb_data();
	void aes192_cfb();
	void aes192_ofb_data();
	void aes192_ofb();
	void aes192_ctr_data();
	void aes192_ctr();

	void aes256_data();
	void aes256();
	void aes256_cbc_data();
	void aes256_cbc();
	void aes256_cbc_pkcs7_data();
	void aes256_cbc_pkcs7();
	void aes256_cfb_data();
	void aes256_cfb();
	void aes256_ofb_data();
	void aes256_ofb();
	void aes256_ctr_data();
	void aes256_ctr();

	void tripleDES_data();
	void tripleDES();

	void des_data();
	void des();
	void des_pkcs7_data();
	void des_pkcs7();
	void des_cbc_data();
	void des_cbc();
	void des_cbc_pkcs7_data();
	void des_cbc_pkcs7();
	void des_cfb_data();
	void des_cfb();
	void des_ofb_data();
	void des_ofb();

	void blowfish_data();
	void blowfish();
	void blowfish_cbc_data();
	void blowfish_cbc();
	void blowfish_cbc_pkcs7_data();
	void blowfish_cbc_pkcs7();
	void blowfish_cfb_data();
	void blowfish_cfb();
	void blowfish_ofb_data();
	void blowfish_ofb();


	void cast5_data();
	void cast5();
private:
	QCA::Initializer* m_init;

};

#endif // CIPHERUNITTEST_H
