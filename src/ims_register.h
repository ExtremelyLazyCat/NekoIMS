// IMS registration with IMS-AKA digest auth
// (RFC 3310 AKAv1-MD5, RFC 4169 AKAv2-MD5).
//
// baresip's own registration client can't answer an AKA challenge (libre's
// credential callback never sees the nonce), so the UA is created with
// regint=0 and REGISTER is sent here instead, on baresip's SIP stack.

#ifndef NEKOIMS_IMS_REGISTER_H
#define NEKOIMS_IMS_REGISTER_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <re.h>

#include "simcard_client.h"

namespace nekoims {

struct ImsRegConfig {
    std::string domain;        // home network domain, e.g. vzims.com
    std::string impi;          // private identity (auth username)
    std::string impu;          // public identity (From/To)
    std::string contact_user;  // Contact user part, must match the UA
    std::string
        outbound;  // P-CSCF route (libre adds ;lr), e.g. sip:[2001:db8::1]
    std::string contact_params;  // appended after Contact URI, ";a;b=c"
    std::vector<std::pair<std::string, std::string>> headers;
    uint32_t expires = 600000;  // TS 24.229 5.1.1.2.1
};

class ImsRegistration {
   public:
    typedef void (*DoneHandler)(void* arg);

    ImsRegistration(struct sip* sip, const ImsRegConfig& cfg,
                    const SimcardClient& sim);
    ~ImsRegistration();

    int start();

    // Deregister (Expires: 0). done is called once finished or timed out.
    void stop(DoneHandler done, void* arg);

    bool registered() const { return registered_; }
    const std::vector<std::string>& service_route() const {
        return service_route_;
    }

   private:
    struct Challenge {
        std::string realm, nonce, opaque, algorithm;
        bool qop_auth = false;
    };
    struct AkaJob;

    static int send_handler(enum sip_transp tp, struct sa* src,
                            const struct sa* dst, struct mbuf* mb,
                            struct mbuf** contp, void* arg);
    static void response_handler(int err, const struct sip_msg* msg, void* arg);
    static void timer_handler(void* arg);
    static void stop_timeout_handler(void* arg);
    static int aka_work(void* arg);
    static void aka_done(int err, void* arg);

    int send_register(const std::string& authorization);
    void on_response(int err, const struct sip_msg* msg);
    void on_ok(const struct sip_msg* msg);
    void on_challenge(const struct sip_msg* msg);
    void on_aka(AkaJob* job);
    void fail(const char* why);
    void finish_stop();
    uint32_t granted_expires(const struct sip_msg* msg) const;
    std::string empty_authorization() const;

    struct sip* sip_;
    ImsRegConfig cfg_;
    SimcardClient sim_;

    struct sip_dialog* dlg_ = nullptr;
    struct sip_request* req_ = nullptr;
    struct tmr tmr_;
    struct tmr stop_tmr_;
    AkaJob* job_ = nullptr;

    uint32_t expires_;            // value sent in the next REGISTER
    unsigned auth_failures_ = 0;  // consecutive 401s to our credentials
    unsigned retry_count_ = 0;
    bool sent_credentials_ = false;
    bool registered_ = false;
    bool stopping_ = false;
    DoneHandler done_ = nullptr;
    void* done_arg_ = nullptr;

    std::vector<std::string> service_route_;
};

}  // namespace nekoims

#endif
