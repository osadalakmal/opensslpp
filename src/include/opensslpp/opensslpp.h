#pragma once

#include "enum.h"
#include <vector>

namespace opensslpp {

struct OpResult {
    int rc;
};

BETTER_ENUM(HASH_TYPE, uint8_t, SHA1, SHA256, SHA384, SHA512, MD5, BLAKE2B256, BLAKE2B512)

class OpenSSLHash {
    public:
    OpResult calculate(HASH_TYPE hashType, const std::string& data, std::vector<char>& hash);
};

}