#include <assert.h>
#include <iostream>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/gcm.h>
#include <cryptopp/modes.h>

#include "BLACKBOX.h"
#include "cipher.h"

namespace BLACKBOX
{
    namespace cipher
    {
        namespace aesgcm
        {
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv)
            {
                const int TAG_SIZE = 16;

                // Encrypted, with Tag
                CryptoPP::SecByteBlock ciphertext;

                try {
                    CryptoPP::GCM<CryptoPP::AES>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), iv, iv.size());
                    // e.SpecifyDataLengths( 0, pdata.size(), 0 );

                    CryptoPP::ByteQueue plain, cipherq;

                    plain.Put(plaintext, plaintext.size());

                    CryptoPP::AuthenticatedEncryptionFilter f1(e, new CryptoPP::Redirector(cipherq), false, TAG_SIZE);
                    plain.TransferTo(f1);
                    f1.MessageEnd();

                    CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    cipherq.TransferTo(sink);

                    ciphertext = block;
                }

                catch (CryptoPP::InvalidArgument& e) {
                    std::cerr << "Caught InvalidArgument..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                } catch (CryptoPP::Exception& e) {
                    std::cerr << "Caught Exception..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                }

                return ciphertext;
            }

            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv)
            {
                const int TAG_SIZE = 16;

                // Recovered plaintext
                CryptoPP::SecByteBlock plaintext;

                try {
                    CryptoPP::GCM<CryptoPP::AES>::Decryption d;
                    d.SetKeyWithIV(key, key.size(), iv, iv.size());

                    CryptoPP::ByteQueue plain, cipherq;

                    cipherq.Put(ciphertext, ciphertext.size());

                    CryptoPP::AuthenticatedDecryptionFilter df(d, new CryptoPP::Redirector(plain), CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE);
                    cipherq.TransferTo(df);
                    df.MessageEnd();

                    CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    plain.TransferTo(sink);

                    bool b = df.GetLastResult();
                    assert(true == b);

                    plaintext = block;
                } catch (CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
                    std::cerr << "Caught HashVerificationFailed..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                } catch (CryptoPP::InvalidArgument& e) {
                    std::cerr << "Caught InvalidArgument..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                } catch (CryptoPP::Exception& e) {
                    std::cerr << "Caught Exception..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                }

                return plaintext;
            }
        } // namespace aesgcm

        namespace aesctr
        {
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr)
            {
                // Ciphertext
                CryptoPP::SecByteBlock ciphertext;

                try {
                    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    plain.Put(plaintext, plaintext.size());

                    CryptoPP::StreamTransformationFilter ef(e, new CryptoPP::Redirector(cipherq));

                    plain.TransferTo(ef);
                    ef.MessageEnd();

                    CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    cipherq.TransferTo(sink);

                    ciphertext = block;
                } catch (CryptoPP::Exception& e) {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return ciphertext;
            }

            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr)
            {
                // Recovered plaintext
                CryptoPP::SecByteBlock plaintext;

                try {
                    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d;
                    d.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    cipherq.Put(ciphertext, ciphertext.size());

                    CryptoPP::StreamTransformationFilter df(d, new CryptoPP::Redirector(plain));

                    cipherq.TransferTo(df);
                    df.MessageEnd();

                    CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    plain.TransferTo(sink);

                    plaintext = block;
                } catch (CryptoPP::Exception& e) {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return plaintext;
            }
        } // namespace aesctr
    }     // namespace cipher
} // namespace BLACKBOX