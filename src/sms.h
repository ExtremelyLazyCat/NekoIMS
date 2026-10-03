// SMS over IMS (TS 24.341), both directions.
//
// The network delivers SMS as SIP MESSAGE with a binary body
// (application/vnd.3gpp.sms or application/vnd.3gpp2.sms), which baresip's
// MESSAGE listener rejects with 415. So this module rewrites the request in place, 
// changing the body to text/plain and the From to the IMS UA's IMPU, and delivers it to baresip.
//
// rx (what SIP clients get)      tx (what SIP clients send)
//   plain       decoded text;      plain       text, encoded to an SMS here
//               undecodable SMS
//               fall back to
//               binary_b64
//   binary_b64  the original       binary_b64  the SMS bytes, as the same
//               bytes as a data                data URI rx produces
//               URI:
//               data:application/vnd.3gpp2.sms;base64,...
//

#ifndef NEKOIMS_SMS_H
#define NEKOIMS_SMS_H

#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <string>
#include <vector>

#include <re.h>

#include "sms_codec.h"

struct ua;
struct cmd;

namespace nekoims {

class ImsRegistration;

struct SmsConfig {
    enum Mode { Off, Plain, BinaryB64 };
    Mode rx = Plain;
    Mode tx = Plain;
    sms::Format format = sms::Format::Unknown;  // Unknown: as last received
    std::string smsc;  // service centre URI or number, default: as received
    bool deliver = true;   // a baresip MESSAGE listener exists
    std::string impu;      // From of what we send
    std::string domain;    // IMS home domain
    std::string outbound;  // P-CSCF, e.g. sip:[2001:db8::1]:5060;transport=udp
    std::string pani;      // P-Access-Network-Info (optional)
};

// The external UA in B2BUA mode
struct SmsLan {
    struct ua* ua = nullptr;
    std::function<bool(const struct sip_msg*)> authorized;  // replies itself
    std::function<std::string()> target;  // where it's reachable, or ""
};

class Sms {
   public:
    Sms(struct sip* sip, const SmsConfig& cfg);
    ~Sms();

    int start();

    void set_ims(const ImsRegistration* reg, struct ua* ims_ua) {
        reg_ = reg;
        ims_ua_ = ims_ua;
    }
    void set_lan(const SmsLan& lan) { lan_ = lan; }

    // Returns false with why set if nothing was sent
    bool send_text(const std::string& to, const std::string& text,
                   std::string& why);
    bool send_raw(sms::Format f, const std::vector<uint8_t>& pdu,
                  const std::string& to, std::string& why);
    bool send_data_uri(const std::string& uri, std::string& why);

   private:
    // A request rewritten in place. Its header fields still point into the
    // original buffer, so that stays alive until the request itself is gone
    // (server transactions keep it for up to 64*T1).
    struct Held {
        struct sip_msg* msg;
        struct mbuf* old_mb;
        std::string from;
    };

    static bool request_handler(const struct sip_msg* msg, void* arg);
    static void response_handler(int err, const struct sip_msg* msg,
                                 void* arg);
    static void gc_handler(void* arg);
    static int cmd_handler(struct re_printf* pf, void* arg);
    static const struct cmd* cmd_table();

    bool on_request(const struct sip_msg* msg);
    void on_lan_message(const struct sip_msg* msg);
    void on_result(const sms::Message& m);
    bool deliver(const struct sip_msg* msg, const std::string& text,
                 const std::string& sender);
    int send_message(const std::string& uri, const struct uri* route,
                     const std::string& hdrs, const char* ctype,
                     const uint8_t* body, size_t len, void* arg);
    void send_ack(const struct sip_msg* msg, sms::Format f,
                  const std::vector<uint8_t>& body);
    std::string ims_headers() const;
    std::string outbound() const;
    bool seen(const std::string& id);
    void rewrite(const struct sip_msg* msg, const std::string& body,
                 const std::string& from);
    void gc();
    sms::Format tx_format() const;

    static Sms* instance_;  // for the command handler

    struct sip* sip_;
    SmsConfig cfg_;
    const ImsRegistration* reg_ = nullptr;
    struct ua* ims_ua_ = nullptr;
    SmsLan lan_;
    struct sip_lsnr* lsnr_ = nullptr;
    struct tmr gc_tmr_;
    bool cmd_ = false;

    // Learned from received SMS
    sms::Format last_format_ = sms::Format::Unknown;
    std::string smsc_uri_;     // From of the last SMS
    std::string smsc_number_;  // 3GPP RP-OA of the last SMS

    unsigned next_ref_;
    unsigned next_id_;
    std::map<unsigned, std::string> pending_;  // ref -> recipient

    std::list<Held> held_;
    std::list<std::pair<std::string, uint64_t> > seen_;  // id, tmr_jiffies
};

}  // namespace nekoims

#endif
