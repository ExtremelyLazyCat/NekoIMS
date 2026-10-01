// Client for simcard-server (USIM-https-server compatible API).

#ifndef NEKOIMS_SIMCARD_CLIENT_H
#define NEKOIMS_SIMCARD_CLIENT_H

#include <cstdint>
#include <string>
#include <vector>

namespace nekoims {

struct AkaResult {
    bool ok = false;            // RES/CK/IK valid
    bool sync_failure = false;  // AUTS valid, network must resync SQN
    std::vector<uint8_t> res, ck, ik, auts;
    std::string error;
};

class SimcardClient {
   public:
    // endpoint: "unix:/path/to/sock" or "http://host:port"
    explicit SimcardClient(const std::string& endpoint);

    bool imsi(std::string& out, std::string& error) const;
    AkaResult authenticate(const std::vector<uint8_t>& rand,
                           const std::vector<uint8_t>& autn) const;

   private:
    bool get(const std::string& query, std::string& body,
             std::string& error) const;

    std::string unix_path_;
    std::string base_url_;
};

}  // namespace nekoims

#endif
