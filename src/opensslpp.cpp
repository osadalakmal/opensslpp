#include "include/opensslpp/opensslpp.h"
#include "openssl_utils.h"

namespace opensslpp {

OpResult OpenSSLHash::calculate(HASH_TYPE hashType, const std::string& data, std::vector<char>& hash) {
    EvpMdCtx mdCtx;
    auto result = mdCtx.init(hashType);
    if (result.rc) return result;
    hash.resize(mdCtx.getMdSize());
    return mdCtx.calculateHash(data, reinterpret_cast<unsigned char*>(&hash[0]));
}


}