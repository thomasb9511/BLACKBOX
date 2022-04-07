#include <iostream>

#include <cryptopp/3way.h>
#include <cryptopp/aes.h>
#include <cryptopp/aria.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/cast.h>
#include <cryptopp/cham.h>
#include <cryptopp/des.h>
#include <cryptopp/files.h>
#include <cryptopp/gost.h>
#include <cryptopp/hight.h>
#include <cryptopp/idea.h>
#include <cryptopp/lea.h>
#include <cryptopp/mars.h>
#include <cryptopp/rc2.h>
#include <cryptopp/rc5.h>
#include <cryptopp/rc6.h>
#include <cryptopp/safer.h>
#include <cryptopp/secblock.h>
#include <cryptopp/seed.h>
#include <cryptopp/serpent.h>
#include <cryptopp/shacal2.h>
#include <cryptopp/shark.h>
#include <cryptopp/simeck.h>
#include <cryptopp/simon.h>
#include <cryptopp/skipjack.h>
#include <cryptopp/speck.h>
#include <cryptopp/square.h>
#include <cryptopp/tea.h>
#include <cryptopp/twofish.h>

#include "blackbox.h"
#include "cipher.h"
#include "transform.h"

template <typename T>
void c()
{
    const BLACKBOX::secure_string key(T::DEFAULT_KEYLENGTH, 0xAA);
    const BLACKBOX::secure_string iv(T::BLOCKSIZE, 0x55);
    const BLACKBOX::secure_string str(T::BLOCKSIZE + 8, 0xFF);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = BLACKBOX::cipher::ctr::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "CTR," << typeid(T).name() << ',' << BLACKBOX::transform::hex::to(pt) << ',' <<
        BLACKBOX::transform::hex::to(aes_data) << ',' << BLACKBOX::transform::hex::to(aes_key) << ',' <<
        BLACKBOX::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void b()
{
    const BLACKBOX::secure_string key(T::DEFAULT_KEYLENGTH, 0xAA);
    const BLACKBOX::secure_string iv(T::BLOCKSIZE, 0x55);
    const BLACKBOX::secure_string str(T::BLOCKSIZE + 8, 0xFF);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = BLACKBOX::cipher::cbc::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "CBC," << typeid(T).name() << ',' << BLACKBOX::transform::hex::to(pt) << ',' <<
        BLACKBOX::transform::hex::to(aes_data) << ',' << BLACKBOX::transform::hex::to(aes_key) << ',' <<
        BLACKBOX::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void a()
{
    if (T::BLOCKSIZE != 16)
        return;

    const BLACKBOX::secure_string key(T::DEFAULT_KEYLENGTH * 2, 0xAA);
    const BLACKBOX::secure_string iv(T::BLOCKSIZE, 0x55);
    const BLACKBOX::secure_string str(T::BLOCKSIZE + 8, 0xFF);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = BLACKBOX::cipher::xts::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "XTS," << typeid(T).name() << ',' << BLACKBOX::transform::hex::to(pt) << ',' <<
        BLACKBOX::transform::hex::to(aes_data) << ',' << BLACKBOX::transform::hex::to(aes_key) << ',' <<
        BLACKBOX::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void d()
{
    const BLACKBOX::secure_string key(T::DEFAULT_KEYLENGTH, 0xAA);
    const BLACKBOX::secure_string iv(T::BLOCKSIZE, 0x55);
    const BLACKBOX::secure_string str(T::BLOCKSIZE + 8, 0xFF);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = BLACKBOX::cipher::cts::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "CTS," << typeid(T).name() << ',' << BLACKBOX::transform::hex::to(pt) << ',' <<
        BLACKBOX::transform::hex::to(aes_data) << ',' << BLACKBOX::transform::hex::to(aes_key) << ',' <<
        BLACKBOX::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void e()
{
    const BLACKBOX::secure_string key(T::DEFAULT_KEYLENGTH, 0xAA);
    const BLACKBOX::secure_string iv(T::BLOCKSIZE, 0x55);
    const BLACKBOX::secure_string str(T::BLOCKSIZE + 8, 0xFF);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = BLACKBOX::cipher::ofb::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "OFB," << typeid(T).name() << ',' << BLACKBOX::transform::hex::to(pt) << ',' <<
        BLACKBOX::transform::hex::to(aes_data) << ',' << BLACKBOX::transform::hex::to(aes_key) << ',' <<
        BLACKBOX::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void f()
{
    const BLACKBOX::secure_string key(T::DEFAULT_KEYLENGTH, 0xAA);
    const BLACKBOX::secure_string iv(T::BLOCKSIZE, 0x55);
    const BLACKBOX::secure_string str(T::BLOCKSIZE + 8, 0xFF);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = BLACKBOX::cipher::cfb::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "CFB," << typeid(T).name() << ',' << BLACKBOX::transform::hex::to(pt) << ',' <<
        BLACKBOX::transform::hex::to(aes_data) << ',' << BLACKBOX::transform::hex::to(aes_key) << ',' <<
        BLACKBOX::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void g()
{
    if (T::BLOCKSIZE != 16)
        return;

    const BLACKBOX::secure_string key(T::DEFAULT_KEYLENGTH, 0xAA);
    const BLACKBOX::secure_string iv(T::BLOCKSIZE, 0x55);
    const BLACKBOX::secure_string str(T::BLOCKSIZE + 8, 0xFF);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = BLACKBOX::cipher::aead::gcm::encrypt<T>(pt, aes_key, aes_iv, T::BLOCKSIZE);

    std::cout << "GCM," << typeid(T).name() << ',' << BLACKBOX::transform::hex::to(pt) << ',' <<
        BLACKBOX::transform::hex::to(aes_data) << ',' << BLACKBOX::transform::hex::to(aes_key) << ',' <<
        BLACKBOX::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void h()
{
    const BLACKBOX::secure_string key(T::DEFAULT_KEYLENGTH, 0xAA);
    const BLACKBOX::secure_string iv(T::BLOCKSIZE, 0x55);
    const BLACKBOX::secure_string str(T::BLOCKSIZE + 8, 0xFF);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = BLACKBOX::cipher::aead::eax::encrypt<T>(pt, aes_key, aes_iv, T::BLOCKSIZE);

    std::cout << "EAX," << typeid(T).name() << ',' << BLACKBOX::transform::hex::to(pt) << ',' <<
        BLACKBOX::transform::hex::to(aes_data) << ',' << BLACKBOX::transform::hex::to(aes_key) << ',' <<
        BLACKBOX::transform::hex::to(aes_iv) << std::endl;
}

int main()
{
    a<CryptoPP::HIGHT>();
    b<CryptoPP::HIGHT>();
    c<CryptoPP::HIGHT>();
    d<CryptoPP::HIGHT>();
    e<CryptoPP::HIGHT>();
    f<CryptoPP::HIGHT>();
    g<CryptoPP::HIGHT>();
    h<CryptoPP::HIGHT>();

    a<CryptoPP::LEA>();
    b<CryptoPP::LEA>();
    c<CryptoPP::LEA>();
    d<CryptoPP::LEA>();
    e<CryptoPP::LEA>();
    f<CryptoPP::LEA>();
    g<CryptoPP::LEA>();
    h<CryptoPP::LEA>();

    a<CryptoPP::DES_EDE3>();
    b<CryptoPP::DES_EDE3>();
    c<CryptoPP::DES_EDE3>();
    d<CryptoPP::DES_EDE3>();
    e<CryptoPP::DES_EDE3>();
    f<CryptoPP::DES_EDE3>();
    g<CryptoPP::DES_EDE3>();
    h<CryptoPP::DES_EDE3>();

    a<CryptoPP::DES_EDE2>();
    b<CryptoPP::DES_EDE2>();
    c<CryptoPP::DES_EDE2>();
    d<CryptoPP::DES_EDE2>();
    e<CryptoPP::DES_EDE2>();
    f<CryptoPP::DES_EDE2>();
    g<CryptoPP::DES_EDE2>();
    h<CryptoPP::DES_EDE2>();

    a<CryptoPP::IDEA>();
    b<CryptoPP::IDEA>();
    c<CryptoPP::IDEA>();
    d<CryptoPP::IDEA>();
    e<CryptoPP::IDEA>();
    f<CryptoPP::IDEA>();
    g<CryptoPP::IDEA>();
    h<CryptoPP::IDEA>();

    a<CryptoPP::SPECK128>();
    b<CryptoPP::SPECK128>();
    c<CryptoPP::SPECK128>();
    d<CryptoPP::SPECK128>();
    e<CryptoPP::SPECK128>();
    f<CryptoPP::SPECK128>();
    g<CryptoPP::SPECK128>();
    h<CryptoPP::SPECK128>();

    a<CryptoPP::SPECK64>();
    b<CryptoPP::SPECK64>();
    c<CryptoPP::SPECK64>();
    d<CryptoPP::SPECK64>();
    e<CryptoPP::SPECK64>();
    f<CryptoPP::SPECK64>();
    g<CryptoPP::SPECK64>();
    h<CryptoPP::SPECK64>();

    a<CryptoPP::SIMECK32>();
    b<CryptoPP::SIMECK32>();
    c<CryptoPP::SIMECK32>();
    d<CryptoPP::SIMECK32>();
    e<CryptoPP::SIMECK32>();
    f<CryptoPP::SIMECK32>();
    g<CryptoPP::SIMECK32>();
    h<CryptoPP::SIMECK32>();

    a<CryptoPP::SIMECK64>();
    b<CryptoPP::SIMECK64>();
    c<CryptoPP::SIMECK64>();
    d<CryptoPP::SIMECK64>();
    e<CryptoPP::SIMECK64>();
    f<CryptoPP::SIMECK64>();
    g<CryptoPP::SIMECK64>();
    h<CryptoPP::SIMECK64>();

    a<CryptoPP::SIMON128>();
    b<CryptoPP::SIMON128>();
    c<CryptoPP::SIMON128>();
    d<CryptoPP::SIMON128>();
    e<CryptoPP::SIMON128>();
    f<CryptoPP::SIMON128>();
    g<CryptoPP::SIMON128>();
    h<CryptoPP::SIMON128>();

    a<CryptoPP::SIMON64>();
    b<CryptoPP::SIMON64>();
    c<CryptoPP::SIMON64>();
    d<CryptoPP::SIMON64>();
    e<CryptoPP::SIMON64>();
    f<CryptoPP::SIMON64>();
    g<CryptoPP::SIMON64>();
    h<CryptoPP::SIMON64>();

    a<CryptoPP::SEED>();
    b<CryptoPP::SEED>();
    c<CryptoPP::SEED>();
    d<CryptoPP::SEED>();
    e<CryptoPP::SEED>();
    f<CryptoPP::SEED>();
    g<CryptoPP::SEED>();
    h<CryptoPP::SEED>();

    a<CryptoPP::SKIPJACK>();
    b<CryptoPP::SKIPJACK>();
    c<CryptoPP::SKIPJACK>();
    d<CryptoPP::SKIPJACK>();
    e<CryptoPP::SKIPJACK>();
    f<CryptoPP::SKIPJACK>();
    g<CryptoPP::SKIPJACK>();
    h<CryptoPP::SKIPJACK>();

    a<CryptoPP::RC6>();
    b<CryptoPP::RC6>();
    c<CryptoPP::RC6>();
    d<CryptoPP::RC6>();
    e<CryptoPP::RC6>();
    f<CryptoPP::RC6>();
    g<CryptoPP::RC6>();
    h<CryptoPP::RC6>();

    a<CryptoPP::Camellia>();
    b<CryptoPP::Camellia>();
    c<CryptoPP::Camellia>();
    d<CryptoPP::Camellia>();
    e<CryptoPP::Camellia>();
    f<CryptoPP::Camellia>();
    g<CryptoPP::Camellia>();
    h<CryptoPP::Camellia>();

    a<CryptoPP::SHACAL2>();
    b<CryptoPP::SHACAL2>();
    c<CryptoPP::SHACAL2>();
    d<CryptoPP::SHACAL2>();
    e<CryptoPP::SHACAL2>();
    f<CryptoPP::SHACAL2>();
    g<CryptoPP::SHACAL2>();
    h<CryptoPP::SHACAL2>();

    a<CryptoPP::AES>();
    b<CryptoPP::AES>();
    c<CryptoPP::AES>();
    d<CryptoPP::AES>();
    e<CryptoPP::AES>();
    f<CryptoPP::AES>();
    g<CryptoPP::AES>();
    h<CryptoPP::AES>();

    a<CryptoPP::Twofish>();
    b<CryptoPP::Twofish>();
    c<CryptoPP::Twofish>();
    d<CryptoPP::Twofish>();
    e<CryptoPP::Twofish>();
    f<CryptoPP::Twofish>();
    g<CryptoPP::Twofish>();
    h<CryptoPP::Twofish>();

    a<CryptoPP::Blowfish>();
    b<CryptoPP::Blowfish>();
    c<CryptoPP::Blowfish>();
    d<CryptoPP::Blowfish>();
    e<CryptoPP::Blowfish>();
    f<CryptoPP::Blowfish>();
    g<CryptoPP::Blowfish>();
    h<CryptoPP::Blowfish>();

    a<CryptoPP::Serpent>();
    b<CryptoPP::Serpent>();
    c<CryptoPP::Serpent>();
    d<CryptoPP::Serpent>();
    e<CryptoPP::Serpent>();
    f<CryptoPP::Serpent>();
    g<CryptoPP::Serpent>();
    h<CryptoPP::Serpent>();

    a<CryptoPP::CHAM128>();
    b<CryptoPP::CHAM128>();
    c<CryptoPP::CHAM128>();
    d<CryptoPP::CHAM128>();
    e<CryptoPP::CHAM128>();
    f<CryptoPP::CHAM128>();
    g<CryptoPP::CHAM128>();
    h<CryptoPP::CHAM128>();

    a<CryptoPP::CHAM64>();
    b<CryptoPP::CHAM64>();
    c<CryptoPP::CHAM64>();
    d<CryptoPP::CHAM64>();
    e<CryptoPP::CHAM64>();
    f<CryptoPP::CHAM64>();
    g<CryptoPP::CHAM64>();
    h<CryptoPP::CHAM64>();

    a<CryptoPP::ARIA>();
    b<CryptoPP::ARIA>();
    c<CryptoPP::ARIA>();
    d<CryptoPP::ARIA>();
    e<CryptoPP::ARIA>();
    f<CryptoPP::ARIA>();
    g<CryptoPP::ARIA>();
    h<CryptoPP::ARIA>();

    a<CryptoPP::MARS>();
    b<CryptoPP::MARS>();
    c<CryptoPP::MARS>();
    d<CryptoPP::MARS>();
    e<CryptoPP::MARS>();
    f<CryptoPP::MARS>();
    g<CryptoPP::MARS>();
    h<CryptoPP::MARS>();

    a<CryptoPP::SHARK>();
    b<CryptoPP::SHARK>();
    c<CryptoPP::SHARK>();
    d<CryptoPP::SHARK>();
    e<CryptoPP::SHARK>();
    f<CryptoPP::SHARK>();
    g<CryptoPP::SHARK>();
    h<CryptoPP::SHARK>();

    a<CryptoPP::Square>();
    b<CryptoPP::Square>();
    c<CryptoPP::Square>();
    d<CryptoPP::Square>();
    e<CryptoPP::Square>();
    f<CryptoPP::Square>();
    g<CryptoPP::Square>();
    h<CryptoPP::Square>();

    a<CryptoPP::GOST>();
    b<CryptoPP::GOST>();
    c<CryptoPP::GOST>();
    d<CryptoPP::GOST>();
    e<CryptoPP::GOST>();
    f<CryptoPP::GOST>();
    g<CryptoPP::GOST>();
    h<CryptoPP::GOST>();

    a<CryptoPP::SAFER_K>();
    b<CryptoPP::SAFER_K>();
    c<CryptoPP::SAFER_K>();
    d<CryptoPP::SAFER_K>();
    e<CryptoPP::SAFER_K>();
    f<CryptoPP::SAFER_K>();
    g<CryptoPP::SAFER_K>();
    h<CryptoPP::SAFER_K>();

    a<CryptoPP::SAFER_SK>();
    b<CryptoPP::SAFER_SK>();
    c<CryptoPP::SAFER_SK>();
    d<CryptoPP::SAFER_SK>();
    e<CryptoPP::SAFER_SK>();
    f<CryptoPP::SAFER_SK>();
    g<CryptoPP::SAFER_SK>();
    h<CryptoPP::SAFER_SK>();

    a<CryptoPP::CAST128>();
    b<CryptoPP::CAST128>();
    c<CryptoPP::CAST128>();
    d<CryptoPP::CAST128>();
    e<CryptoPP::CAST128>();
    f<CryptoPP::CAST128>();
    g<CryptoPP::CAST128>();
    h<CryptoPP::CAST128>();

    a<CryptoPP::CAST256>();
    b<CryptoPP::CAST256>();
    c<CryptoPP::CAST256>();
    d<CryptoPP::CAST256>();
    e<CryptoPP::CAST256>();
    f<CryptoPP::CAST256>();
    g<CryptoPP::CAST256>();
    h<CryptoPP::CAST256>();

    a<CryptoPP::ThreeWay>();
    b<CryptoPP::ThreeWay>();
    c<CryptoPP::ThreeWay>();
    d<CryptoPP::ThreeWay>();
    e<CryptoPP::ThreeWay>();
    f<CryptoPP::ThreeWay>();
    g<CryptoPP::ThreeWay>();
    h<CryptoPP::ThreeWay>();

    a<CryptoPP::TEA>();
    b<CryptoPP::TEA>();
    c<CryptoPP::TEA>();
    d<CryptoPP::TEA>();
    e<CryptoPP::TEA>();
    f<CryptoPP::TEA>();
    g<CryptoPP::TEA>();
    h<CryptoPP::TEA>();

    a<CryptoPP::XTEA>();
    b<CryptoPP::XTEA>();
    c<CryptoPP::XTEA>();
    d<CryptoPP::XTEA>();
    e<CryptoPP::XTEA>();
    f<CryptoPP::XTEA>();
    g<CryptoPP::XTEA>();
    h<CryptoPP::XTEA>();

    a<CryptoPP::RC2>();
    b<CryptoPP::RC2>();
    c<CryptoPP::RC2>();
    d<CryptoPP::RC2>();
    e<CryptoPP::RC2>();
    f<CryptoPP::RC2>();
    g<CryptoPP::RC2>();
    h<CryptoPP::RC2>();

    a<CryptoPP::RC5>();
    b<CryptoPP::RC5>();
    c<CryptoPP::RC5>();
    d<CryptoPP::RC5>();
    e<CryptoPP::RC5>();
    f<CryptoPP::RC5>();
    g<CryptoPP::RC5>();
    h<CryptoPP::RC5>();

    a<CryptoPP::DES_XEX3>();
    b<CryptoPP::DES_XEX3>();
    c<CryptoPP::DES_XEX3>();
    d<CryptoPP::DES_XEX3>();
    e<CryptoPP::DES_XEX3>();
    f<CryptoPP::DES_XEX3>();
    g<CryptoPP::DES_XEX3>();
    h<CryptoPP::DES_XEX3>();
}
