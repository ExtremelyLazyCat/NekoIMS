// Back-to-back user agent: lets an external SIP UA (desk phone, softphone,
// PBX trunk) call through NekoIMS.
//
// Unlike the stock module in baresip-apps this works in both directions, rewrites 
// URIs forthe IMS core, and drives the bridge from bevents instead of replacing the
// calls' event handlers, so the IMS leg keeps the BYE-header and early-media
// handling in main.cpp.

#ifndef NEKOIMS_B2BUA_H
#define NEKOIMS_B2BUA_H

#include <list>
#include <string>

#include <re.h>
#include <baresip.h>

#include "netns.h"

namespace nekoims {

struct B2buaConfig {
    std::string username = "nekoims";  // LAN account user, digest username
    std::string password;              // empty: no authentication
    std::string target;  // fixed URI for IMS-terminated calls (optional)
    std::string audio_codecs = "PCMU/8000,PCMA/8000";  // LAN leg
    std::string listen;  // only accept the external UA on this address
    std::string netns;   // listen is in this network namespace (Linux)
    std::string ims_domain;  // request URIs for + toward IMS
};

class B2bua {
   public:
    B2bua(const B2buaConfig& cfg, struct ua* ims_ua);
    ~B2bua();

    int start();

    // For SMS from/to the external UA
    struct ua* lan_ua() const { return lan_ua_; }
    bool authorized(const struct sip_msg* msg);  // replies 401/403 itself
    std::string lan_target();                    // "" if none

    // Namespace the external UA's side lives in, see b2bua.netns
    void set_netns(Netns* ns) { netns_ = ns; }

   private:
    struct Session {
        B2bua* owner;
        struct ua* ua_in;
        struct call* in;  // leg that sent us the INVITE
        struct ua* ua_out;
        struct call* out;  // leg we dialed
        uint16_t scode;    // reject code when out couldn't be dialed
        unsigned answer_tries;
        struct tmr tmr;  // deferred reject or answer, used in new_session()
        struct tmr rebridge_tmr;  // see rebridge_handler()
    };

    static void event_handler(enum bevent_ev ev, struct bevent* event,
                              void* arg);
    static bool request_handler(const struct sip_msg* msg, void* arg);
    static int ha1_handler(uint8_t* ha1, const struct pl* user,
                           const char* realm, void* arg);
    static void reject_handler(void* arg);
    static void answer_handler(void* arg);
    static void rebridge_handler(void* arg);

    void on_event(enum bevent_ev ev, struct bevent* event);
    void on_connect(const struct sip_msg* msg);
    void on_register(const struct sip_msg* msg);
    void new_session(struct ua* ua, struct call* call);
    void close_session(std::list<Session>::iterator it, struct call* closed,
                       const char* text);
    std::list<Session>::iterator find(const struct call* call);

    B2buaConfig cfg_;
    struct ua* ims_ua_;
    struct ua* lan_ua_ = nullptr;
    struct sa listen_;  // unset: any local address
    Netns* netns_ = nullptr;
    struct sip_lsnr* lsnr_ = nullptr;
    bool bevent_ = false;

    std::list<Session> sessions_;

    std::string binding_;  // Contact of the registered external UA
    uint64_t binding_expires_ = 0;  // tmr_jiffies()
};

}  // namespace nekoims

#endif
