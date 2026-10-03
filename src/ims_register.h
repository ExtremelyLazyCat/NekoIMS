// IMS registration with IMS-AKA digest auth
// (RFC 3310 AKAv1-MD5, RFC 4169 AKAv2-MD5).
//
// baresip's own registration client can't answer an AKA challenge (libre's
// credential callback never sees the nonce), so the UA is created with
// regint=0 and REGISTER is sent here instead, on baresip's SIP stack.

#ifndef NEKOIMS_IMS_REGISTER_H
#define NEKOIMS_IMS_REGISTER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <re.h>

#include "ipsec.h"
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
    std::string aka_app = "isim";  // "isim" or "usim"
    std::string user_agent;
    // sec-agree with IMS IPsec (TS 33.203, RFC 3329) on our SIP port.
    bool sec_agree = false;
    uint16_t sec_port = 5060;
    std::string sec_proto = "udp";
    // Called when outbound() / security_verify() change.
    std::function<void()> on_route_change;
    // Called when preferred_identity() changes.
    std::function<void()> on_identity_change;
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

    // Where other requests go: the P-CSCF's protected port once a
    // registration over the SAs succeeded, else cfg.outbound.
    const std::string& outbound() const {
        return active_ ? route_ : cfg_.outbound;
    }
    // The identity to assert (P-Preferred-Identity): of the P-Associated-URIs
    // of the last registration, the first sip: with a +number, else the
    // first tel:, else the first; cfg.impu before any. An ISIM's IMPU is
    // often a barred, IMSI-based one that can't make calls (TS 24.229
    // 5.1.1.2.1).
    std::string preferred_identity() const;

    // Security-Verify for requests over the SAs, "" when unprotected.
    std::string security_verify() const {
        return active_ ? active_verify_ : std::string();
    }
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
    void new_spis();
    void new_dialog();
    void set_route(const std::string& route);
    void drop_ipsec();
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

    struct sip_request* req_ = nullptr;
    std::string call_id_, from_tag_;
    uint32_t cseq_ = 0;
    std::string route_;  // see outbound()
    struct uri route_uri_;
    struct sa local_;    // our address as libre sent the last REGISTER
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
    std::vector<std::string> associated_;  // P-Associated-URI, bare URIs

    // sec-agree
    uint32_t spi_c_ = 0, spi_s_ = 0;  // in our current Security-Client
    std::string security_verify_;     // Security-Server of the last 401
    bool have_server_ = false;
    SecMech server_;                  // its entry we install
    struct sa server_addr_;           // the P-CSCF that sent it
    std::unique_ptr<IpsecSet> pending_;  // installed, REGISTER in flight
    std::unique_ptr<IpsecSet> active_;   // of the current registration
    std::string active_verify_;
};

}  // namespace nekoims

#endif
