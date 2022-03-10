#pragma once

namespace BLACKBOX
{
    namespace rng
    {
        class CombinedRNG: public CryptoPP::RandomNumberGenerator
        {
        public:
            CombinedRNG(CryptoPP::RandomNumberGenerator& rng1,
                        CryptoPP::RandomNumberGenerator& rng2)
                : m_rng1(rng1)
                , m_rng2(rng2)
            {
            }

            bool CanIncorporateEntropy() const
            {
                return m_rng1.CanIncorporateEntropy() || m_rng2.CanIncorporateEntropy();
            }

            void IncorporateEntropy(const CryptoPP::byte* input, size_t length)
            {
                if (m_rng1.CanIncorporateEntropy())
                    m_rng1.IncorporateEntropy(input, length);
                if (m_rng2.CanIncorporateEntropy())
                    m_rng2.IncorporateEntropy(input, length);
            }

            void GenerateBlock(CryptoPP::byte* output, size_t size)
            {
                CryptoPP::RandomNumberSource(m_rng1, size, true, new CryptoPP::ArraySink(output, size));
                CryptoPP::RandomNumberSource(m_rng2, size, true, new CryptoPP::ArrayXorSink(output, size));
            }

        private:
            CryptoPP::RandomNumberGenerator &m_rng1, &m_rng2;
        };

        sympack                rand_sympack();
        CryptoPP::SecByteBlock randblock(const int bytes);

        std::string randstrng(const int len);
        std::string rdprime(unsigned int bytes);

        namespace RDSEED
        {
            sympack                rand_sympack();
            CryptoPP::SecByteBlock randblock(const int bytes);

            std::string randstrng(const int len);
            std::string rdprime(unsigned int bytes);
        } // namespace RDSEED

        namespace RDRAND
        {
            sympack                rand_sympack();
            CryptoPP::SecByteBlock randblock(const int bytes);

            std::string randstrng(const int len);
            std::string rdprime(unsigned int bytes);
        } // namespace RDRAND

        namespace X917
        {
            sympack                rand_sympack();
            CryptoPP::SecByteBlock randblock(const int bytes);

            std::string randstrng(const int len);
            std::string rdprime(unsigned int bytes);
        } // namespace X917

        namespace X931
        {
            sympack                rand_sympack();
            CryptoPP::SecByteBlock randblock(const int bytes);

            std::string randstrng(const int len);
            std::string rdprime(unsigned int bytes);
        } // namespace X931
    }     // namespace rng
} // namespace BLACKBOX