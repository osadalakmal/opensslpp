#include <gtest/gtest.h>
#include <sstream>
#include <opensslpp/opensslpp.h>

using namespace opensslpp;
using namespace ::testing;

namespace {
    std::string printToHex(const char* arr, int size) {
        static const char halpha[] = "0123456789abcdef";
        std::string result;
        result.reserve(size * 2);
        for (int i = 0; i < size; i++)
        {
            result.push_back(halpha[(arr[i] >> 4) & 0xF]);
            result.push_back(halpha[arr[i] & 0xF]);
        }
        return result;
    }
}

class OpensslppTest : public ::TestWithParam<std::pair<HASH_TYPE, const std::string>> {
};

TEST_P(OpensslppTest, Hash_Values_Are_Correct){
    OpenSSLHash hashObj;
    std::vector<char> rawHash;
    auto result = hashObj.calculate(GetParam().first, "Hello World!", rawHash);
    ASSERT_EQ(1, result.rc);
    ASSERT_STREQ(GetParam().second.c_str(), printToHex(&rawHash[0], rawHash.size()).c_str());
}

INSTANTIATE_TEST_SUITE_P(HashTypeInstantiate, OpensslppTest, 
    Values(std::pair<const HASH_TYPE, const std::string>(HASH_TYPE::MD5, "ed076287532e86365e841e92bfc50d8c"),
           std::pair<const HASH_TYPE, const std::string>(HASH_TYPE::SHA1, "2ef7bde608ce5404e97d5f042f95f89f1c232871"),
           std::pair<const HASH_TYPE, const std::string>(HASH_TYPE::SHA256, "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"),
           std::pair<const HASH_TYPE, const std::string>(HASH_TYPE::SHA512, "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8")));