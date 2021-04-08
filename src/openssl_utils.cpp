#include "openssl_utils.h"

namespace opensslpp {

EvpMdCtx::EvpMdCtx() {
    m_evpCtx = EVP_MD_CTX_new();
}

OpResult EvpMdCtx::init(HASH_TYPE hashType) {
    auto md = EVP_get_digestbyname(hashType._to_string());
    if (!EVP_DigestInit_ex(m_evpCtx, md, NULL)) {
        return OpResult {.rc = 1};
    }
    return OpResult {.rc = 0};
}

unsigned int EvpMdCtx::getMdSize() {
    return EVP_MD_CTX_size(m_evpCtx);
}

OpResult EvpMdCtx::calculateHash(const std::string& data, unsigned char* hash) {
    EVP_DigestUpdate(m_evpCtx, data.c_str(), data.size());
    unsigned int mdLen = 0;
    if (EVP_DigestFinal_ex(m_evpCtx, &hash[0], &mdLen)) {
        return OpResult {.rc = 1};
    }
    return OpResult {.rc = 0};
}

EvpMdCtx::~EvpMdCtx() {
    EVP_MD_CTX_free(m_evpCtx);
}

}