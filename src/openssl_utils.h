#include <opensslpp/opensslpp.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

namespace opensslpp {

class EvpMdCtx {
    public:
    EvpMdCtx();
    ~EvpMdCtx();
    OpResult init(HASH_TYPE hashType);
    unsigned int getMdSize();
    OpResult calculateHash(const std::string& data, unsigned char* hash);
    private:
    EVP_MD_CTX* m_evpCtx;
    EVP_MD* m_evpMd;
};

}