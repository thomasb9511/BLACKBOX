#include <iostream>
#include <string.h>

#include <cryptopp/blake2.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/hmac.h>
#include <cryptopp/keccak.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha3.h>
#include <cryptopp/whrlpool.h>

#include "blackbox.h"
#include "hash.h"
#include "transform.h"

namespace BLACKBOX
{
    template <typename F, typename T>
    CryptoPP::SecByteBlock prompt(char bit)
    {
        CryptoPP::SecByteBlock password;

        {
            secure_string pwd;

            std::cout << "Please enter parameter " << bit << ":";

            SetStdinEcho(false);

            std::cin >> pwd;

            SetStdinEcho(true);

            std::cout << "\n";

            CryptoPP::SecByteBlock pss((const unsigned char*)(pwd.data()), pwd.size());

            CryptoPP::SecByteBlock h_1 = hash::hash<T>(pss);
            CryptoPP::SecByteBlock h_2 = hash::hash<F>(pss);

            std::fill_n(&pwd[0], pwd.capacity() - 1, 0xff); // really overwrite

            password = transform::logical::xo(h_1, h_2);
        }

        std::string salt   = bit + "1234567890 - Salt string.";
        std::string deriv  = bit + "ABCDEFGHIJ - Derivation string.";
        std::string salt2  = bit + "JIHGFEDCBA - Salt string.";
        std::string deriv2 = bit + "0987654321 - Derivation string.";

        CryptoPP::SecByteBlock past = hash::hkdf<T>(password, salt, deriv);

        CryptoPP::SecByteBlock present = hash::hkdf<F>(password, salt2, deriv2);

        return transform::logical::xo(present, past);
    }
} // namespace BLACKBOX

template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::SHA3_512, CryptoPP::BLAKE2b>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::SHA3_512, CryptoPP::Keccak_512>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::SHA3_512, CryptoPP::Whirlpool>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::BLAKE2b, CryptoPP::SHA3_512>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::BLAKE2b, CryptoPP::Keccak_512>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::BLAKE2b, CryptoPP::Whirlpool>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::Keccak_512, CryptoPP::SHA3_512>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::Keccak_512, CryptoPP::BLAKE2b>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::Keccak_512, CryptoPP::Whirlpool>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::Whirlpool, CryptoPP::SHA3_512>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::Whirlpool, CryptoPP::BLAKE2b>(char bit);
template CryptoPP::SecByteBlock BLACKBOX::prompt<CryptoPP::Whirlpool, CryptoPP::Keccak_512>(char bit);
