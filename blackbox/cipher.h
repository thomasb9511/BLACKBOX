#pragma once

namespace BLACKBOX
{
    namespace cipher
    {
        namespace aesgcm
        {
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
        } // namespace aesgcm
        namespace aesctr
        {
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
        } // namespace aesctr
    }     // namespace cipher
} // namespace BLACKBOX