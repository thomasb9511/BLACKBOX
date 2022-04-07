#include "transform.h"

#include <iostream>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>

#include "BLACKBOX.h"

namespace BLACKBOX
{
    namespace transform
    {
        namespace hex
        {
            std::string to(std::string& input)
            {
                const CryptoPP::byte* pbData   = (CryptoPP::byte*)input.data();
                unsigned int          nDataLen = input.length();

                std::string output;

                try
                {
                    CryptoPP::HexEncoder hex(new CryptoPP::StringSink(output));
                    // @suppress("Abstract class cannot be instantiated")
                    hex.Put(pbData, nDataLen);
                    hex.MessageEnd();
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return output;
            }

            std::string to(CryptoPP::SecByteBlock& input)
            {
                std::string output;

                try
                {
                    CryptoPP::HexEncoder hex(new CryptoPP::StringSink(output));
                    // @suppress("Abstract class cannot be instantiated")
                    hex.Put(input, input.size());
                    hex.MessageEnd();
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return output;
            }

            std::string from(std::string& input)
            {
                const CryptoPP::byte* pbData   = (CryptoPP::byte*)input.data();
                unsigned int          nDataLen = input.length();

                std::string output;

                try
                {
                    CryptoPP::HexDecoder hex(new CryptoPP::StringSink(output));
                    // @suppress("Abstract class cannot be instantiated")
                    hex.Put(pbData, nDataLen);
                    hex.MessageEnd();
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return output;
            }

            std::string from(CryptoPP::SecByteBlock& input)
            {
                std::string output;

                try
                {
                    CryptoPP::HexDecoder hex(new CryptoPP::StringSink(output));
                    // @suppress("Abstract class cannot be instantiated")
                    hex.Put(input, input.size());
                    hex.MessageEnd();
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return output;
            }

            namespace bytes
            {
                CryptoPP::SecByteBlock to(CryptoPP::SecByteBlock& input)
                {
                    CryptoPP::SecByteBlock output;

                    try
                    {
                        CryptoPP::HexEncoder hex(new CryptoPP::ArraySink(output, input.size() * 2));
                        // @suppress("Abstract class cannot be instantiated")
                        hex.Put(input, input.size());
                        hex.MessageEnd();
                    }
                    catch (CryptoPP::Exception& e)
                    {
                        std::cerr << e.what() << std::endl;
                        exit(1);
                    }

                    return output;
                }

                CryptoPP::SecByteBlock from(CryptoPP::SecByteBlock& input)
                {
                    CryptoPP::SecByteBlock output;

                    try
                    {
                        CryptoPP::HexDecoder hex(new CryptoPP::ArraySink(output, input.size() / 2));
                        // @suppress("Abstract class cannot be instantiated")
                        hex.Put(input, input.size());
                        hex.MessageEnd();
                    }
                    catch (CryptoPP::Exception& e)
                    {
                        std::cerr << e.what() << std::endl;
                        exit(1);
                    }

                    return output;
                }
            } // namespace bytes
        }     // namespace hex

        namespace logical
        {
            std::string xo(std::string& value, std::string& key)
            {
                std::string       retval(value);
                long unsigned int klen = key.length();
                long unsigned int vlen = value.length();
                unsigned long int k    = 0;
                unsigned long int v    = 0;
                for (; v < vlen; v++)
                {
                    retval[v] = value[v] ^ key[k];
                    k         = (++k < klen ? k : 0);
                }
                return retval;
            }

            CryptoPP::SecByteBlock interleave(CryptoPP::SecByteBlock& a, CryptoPP::SecByteBlock& b)
            {
                const size_t len_a = a.size();
                const size_t len_b = b.size();

                const size_t max_len = std::max(len_a, len_b);

                CryptoPP::SecByteBlock interleaved(max_len * 2);

                for (std::size_t i = 0; i < max_len; ++i)
                {
                    interleaved[i * 2]     = a[i % len_a];
                    interleaved[i * 2 + 1] = b[i % len_b];
                }

                return interleaved;
            }

            CryptoPP::SecByteBlock xo(CryptoPP::SecByteBlock& a, CryptoPP::SecByteBlock& b)
            {
                CryptoPP::SecByteBlock key = a;

                for (size_t i = 0; i < key.size(); i++)
                    key[i]    = a[i] ^ b[i];

                return key;
            }

            void rotate_(CryptoPP::SecByteBlock& in, unsigned int n)
            {
                for (size_t i = 0; i < in.size(); ++i)
                {
                    n = ((~n * (i + n)) + 1) % 8;

                    in[i] = (in[i] << n) | (in[i] >> (8 - n));
                }
            }
        } // namespace logical
    }     // namespace transform
}         // namespace BLACKBOX
