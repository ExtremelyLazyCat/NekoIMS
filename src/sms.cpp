#include "sms.h"

#include <cstring>

#include <baresip.h>

#include "ims_register.h"

namespace nekoims {

namespace {

const uint64_t kGcIntervalMs = 10000;
const uint64_t kSeenMs = 15 * 60 * 1000;  // network retries come sooner
const size_t kSeenMax = 64;
const char* const kDataPrefix = "data:";
const char* const kB64Marker = ";base64,";

std::string pl_str(const struct pl& pl) {
    return pl_isset(&pl) ? std::string(pl.p, pl.l) : std::string();
}

std::string data_uri(sms::Format f, const uint8_t* p, size_t n) {
    return std::string(kDataPrefix) + sms::format_mime(f) + kB64Marker +
           sms::base64(p, n);
}

bool is_number(const std::string& s) {
    return !s.empty() && s.find_first_not_of("+0123456789*#") == std::string::npos;
}

// What menu/ctrl_tcp show as the sender; the network's From is the SMS
// service centre, not the person.
std::string sender_uri(const std::string& sender) {
    return is_number(sender) ? "tel:" + sender : std::string();
}

// Digits of tel:+1555..., sip:+1555...@host or a bare number
std::string uri_number(const std::string& uri) {
    std::string s = uri;
    const size_t colon = s.find(':');
    if (colon != std::string::npos) s = s.substr(colon + 1);
    s = s.substr(0, s.find_first_of("@;"));
    return is_number(s) ? s : std::string();
}

unsigned pending_key(sms::Format f, unsigned ref) {
    return (f == sms::Format::Gpp2 ? 0x100 : 0) | (ref & 0xff);
}

}  // namespace

Sms* Sms::instance_ = nullptr;

Sms::Sms(struct sip* sip, const SmsConfig& cfg) : sip_(sip), cfg_(cfg) {
    tmr_init(&gc_tmr_);
    next_ref_ = rand_u32();
    next_id_ = rand_u32();

    if (!cfg_.smsc.empty() && cfg_.smsc.find(':') == std::string::npos)
        cfg_.smsc = "tel:" + cfg_.smsc;
}

Sms::~Sms() {
    tmr_cancel(&gc_tmr_);
    mem_deref(lsnr_);
    if (cmd_) cmd_unregister(baresip_commands(), cmd_table());
    if (instance_ == this) instance_ = nullptr;

    // A request still referenced elsewhere keeps its original buffer; this
    // is shutdown, so leaking it beats a use-after-free.
    for (std::list<Held>::iterator it = held_.begin(); it != held_.end();
         ++it) {
        const bool last = mem_nrefs(it->msg) == 1;
        mem_deref(it->msg);
        if (last) mem_deref(it->old_mb);
    }
}

int Sms::start() {
    // Must run before conf_modules(): menu and ctrl_tcp create baresip's
    // MESSAGE listener there, and libre asks listeners in the order added.
    int err = sip_listen(&lsnr_, sip_, true, request_handler, this);
    if (err) return err;

    if (cfg_.tx != SmsConfig::Off) {
        instance_ = this;
        err = cmd_register(baresip_commands(), cmd_table(), 1);
        if (err) return err;
        cmd_ = true;
    }
    return 0;
}

bool Sms::request_handler(const struct sip_msg* msg, void* arg) {
    return static_cast<Sms*>(arg)->on_request(msg);
}

bool Sms::on_request(const struct sip_msg* msg) {
    if (pl_strcmp(&msg->met, "MESSAGE")) return false;

    if (lan_.ua && uag_find_msg(msg) == lan_.ua) {
        on_lan_message(msg);
        return true;
    }

    if (cfg_.rx == SmsConfig::Off ||
        pl_strcasecmp(&msg->ctyp.type, "application"))
        return false;

    const sms::Format format =
        sms::format_from_subtype(pl_str(msg->ctyp.subtype));
    if (format == sms::Format::Unknown) return false;

    const uint8_t* body = mbuf_buf(msg->mb);
    const size_t len = mbuf_get_left(msg->mb);

    info("sms: %r from %r: %w\n", &msg->ctyp.subtype, &msg->from.auri, body,
         len);

    sms::Message m;
    const bool ok = sms::decode(format, body, len, m);
    if (!ok) warning("sms: malformed %s\n", sms::format_mime(format));

    if (ok && m.kind == sms::Message::Ack) {
        on_result(m);
        if (cfg_.rx == SmsConfig::Plain) {
            (void)sip_treply(NULL, sip_, msg, 200, "OK");
            return true;
        }
        // binary_b64: pass the network's answer on to the client
        return deliver(msg, data_uri(format, body, len), std::string());
    }

    if (!m.ack.empty()) send_ack(msg, format, m.ack);

    if (ok) {
        last_format_ = format;
        smsc_uri_ = pl_str(msg->from.auri);
        if (!m.smsc.empty()) smsc_number_ = m.smsc;
    }

    // Retransmitted by the network (our ack got lost): ack again, but don't
    // deliver twice.
    if (ok && seen(m.id)) {
        info("sms: duplicate %s, not delivered again\n", m.id.c_str());
        (void)sip_treply(NULL, sip_, msg, 200, "OK");
        return true;
    }

    std::string text;
    if (cfg_.rx == SmsConfig::Plain && m.has_text)
        text = m.text;
    else
        text = data_uri(format, body, len);

    info("sms: from %s%s%s: %s\n", m.sender.empty() ? "?" : m.sender.c_str(),
         m.timestamp.empty() ? "" : " at ", m.timestamp.c_str(),
         text.c_str());

    return deliver(msg, text, m.sender);
}

// Returns what the SIP listener should: false to let baresip deliver it
bool Sms::deliver(const struct sip_msg* msg, const std::string& text,
                  const std::string& sender) {
    // External UA (B2BUA mode), shown as coming from the SMS's sender
    const std::string target = lan_.target ? lan_.target() : std::string();
    if (!target.empty()) {
        struct uri route;
        struct pl pl;
        pl_set_str(&pl, target.c_str());
        if (!uri_decode(&route, &pl)) {
            const std::string from =
                "sip:" + (is_number(sender) ? sender : std::string("sms")) +
                "@" + cfg_.domain;
            const std::string hdrs = "To: <" + target + ">\r\nFrom: <" + from +
                                     ">;tag=" + std::to_string(rand_u32()) +
                                     "\r\n";
            (void)send_message(
                target, &route, hdrs, "text/plain;charset=utf-8",
                reinterpret_cast<const uint8_t*>(text.data()), text.size(),
                NULL);
        }
    }

    if (!cfg_.deliver) {
        (void)sip_treply(NULL, sip_, msg, 200, "OK");
        return true;
    }

    // baresip's listener runs next, sees text/plain and answers 200 itself
    rewrite(msg, text, sender_uri(sender));
    return false;
}

// A MESSAGE from the external UA: an SMS to send
void Sms::on_lan_message(const struct sip_msg* msg) {
    if (lan_.authorized && !lan_.authorized(msg)) return;

    const std::string to = pl_str(msg->uri.user);
    const uint8_t* body = mbuf_buf(msg->mb);
    const size_t len = mbuf_get_left(msg->mb);
    std::string why;
    bool sent = false;

    const sms::Format raw =
        pl_strcasecmp(&msg->ctyp.type, "application")
            ? sms::Format::Unknown
            : sms::format_from_subtype(pl_str(msg->ctyp.subtype));

    if (raw != sms::Format::Unknown) {
        sent = send_raw(raw, std::vector<uint8_t>(body, body + len), to, why);
    } else if (msg_ctype_cmp(&msg->ctyp, "text", "plain")) {
        const std::string text(reinterpret_cast<const char*>(body), len);
        if (cfg_.tx == SmsConfig::Plain)
            sent = send_text(to, text, why);
        else if (cfg_.tx == SmsConfig::BinaryB64)
            sent = send_data_uri(text, why);
        else
            why = "sending SMS is disabled";
    } else {
        (void)sip_treplyf(NULL, NULL, sip_, msg, false, 415,
                          "Unsupported Media Type",
                          "Accept: text/plain, application/vnd.3gpp.sms, "
                          "application/vnd.3gpp2.sms\r\n"
                          "Content-Length: 0\r\n\r\n");
        return;
    }

    if (sent) {
        (void)sip_treply(NULL, sip_, msg, 202, "Accepted");
        return;
    }

    warning("sms: not sent: %s\n", why.c_str());
    (void)sip_treplyf(NULL, NULL, sip_, msg, false, 488, "Not Acceptable Here",
                      "Warning: 399 nekoims \"%s\"\r\n"
                      "Content-Length: 0\r\n\r\n",
                      why.c_str());
}

sms::Format Sms::tx_format() const {
    if (cfg_.format != sms::Format::Unknown) return cfg_.format;
    if (last_format_ != sms::Format::Unknown) return last_format_;
    return sms::Format::Gpp;
}

bool Sms::send_text(const std::string& to, const std::string& text,
                    std::string& why) {
    const sms::Format f = tx_format();
    const std::string smsc =
        cfg_.smsc.empty() ? smsc_number_ : uri_number(cfg_.smsc);
    const unsigned ref = f == sms::Format::Gpp2 ? next_ref_ % 64
                                                : next_ref_ % 256;
    std::vector<uint8_t> pdu;

    if (!sms::encode_submit(f, to, text, ref, next_id_ & 0xffff, smsc, pdu,
                            why))
        return false;
    ++next_ref_;
    ++next_id_;

    return send_raw(f, pdu, to, why);
}

bool Sms::send_data_uri(const std::string& uri, std::string& why) {
    const size_t marker = uri.find(kB64Marker);
    if (uri.compare(0, std::strlen(kDataPrefix), kDataPrefix) ||
        marker == std::string::npos)
        return why = "expected data:application/vnd.3gpp(2).sms;base64,...",
               false;

    const std::string mime =
        uri.substr(std::strlen(kDataPrefix), marker - std::strlen(kDataPrefix));
    const sms::Format f = !mime.compare(0, 12, "application/")
                              ? sms::format_from_subtype(mime.substr(12))
                              : sms::Format::Unknown;
    if (f == sms::Format::Unknown)
        return why = "unknown SMS format " + mime, false;

    std::vector<uint8_t> pdu;
    if (!sms::unbase64(uri.substr(marker + std::strlen(kB64Marker)), pdu) ||
        pdu.empty())
        return why = "bad base64", false;

    return send_raw(f, pdu, std::string(), why);
}

// TS 24.341 5.3.1.2: SMS to the service centre, recipient inside the PDU
bool Sms::send_raw(sms::Format f, const std::vector<uint8_t>& pdu,
                   const std::string& to, std::string& why) {
    const std::string smsc = cfg_.smsc.empty() ? smsc_uri_ : cfg_.smsc;
    if (smsc.empty())
        return why = "no SMSC address (set sms.smsc or receive an SMS first)",
               false;

    struct uri route;
    struct pl pl;
    pl_set_str(&pl, cfg_.outbound.c_str());
    if (uri_decode(&route, &pl)) return why = "bad P-CSCF URI", false;

    unsigned ref = 0;
    const bool has_ref = sms::submit_ref(f, pdu.data(), pdu.size(), ref);
    const std::string label = to.empty() ? "?" : to;

    const std::string hdrs = "To: <" + smsc + ">\r\nFrom: <" + cfg_.impu +
                             ">;tag=" + std::to_string(rand_u32()) + "\r\n" +
                             ims_headers();
    int err = send_message(smsc, &route, hdrs, sms::format_mime(f),
                           pdu.data(), pdu.size(), this);
    if (err) {
        char buf[64];
        re_snprintf(buf, sizeof(buf), "%m", err);
        return why = buf, false;
    }

    if (has_ref) pending_[pending_key(f, ref)] = label;
    info("sms: sending %s to %s (ref %u): %w\n", sms::format_mime(f),
         label.c_str(), ref, pdu.data(), pdu.size());
    return true;
}

void Sms::on_result(const sms::Message& m) {
    const unsigned key = pending_key(m.format, m.ref);
    std::map<unsigned, std::string>::iterator it = pending_.find(key);
    const std::string to = it != pending_.end() ? it->second : "?";
    if (it != pending_.end()) pending_.erase(it);

    if (m.accepted)
        info("sms: to %s (ref %u) accepted by the SMSC\n", to.c_str(), m.ref);
    else
        warning("sms: to %s (ref %u) rejected, cause %u\n", to.c_str(), m.ref,
                m.cause);

    module_event("sms", m.accepted ? "sent" : "failed", ims_ua_, NULL,
                 "%u,%s,%u", m.ref, to.c_str(), m.cause);
}

std::string Sms::ims_headers() const {
    std::string hdrs = "Route: <" + cfg_.outbound + ";lr>\r\n";
    if (reg_) {
        const std::vector<std::string>& sr = reg_->service_route();
        for (size_t i = 0; i < sr.size(); ++i)
            hdrs += "Route: " + sr[i] + "\r\n";
    }
    hdrs += "P-Preferred-Identity: <" + cfg_.impu + ">\r\n";
    if (!cfg_.pani.empty())
        hdrs += "P-Access-Network-Info: " + cfg_.pani + "\r\n";
    hdrs += "Request-Disposition: no-fork\r\n";
    return hdrs;
}

// Out-of-dialog MESSAGE. hdrs must have To, From (with tag) and any Route;
// arg non-NULL means it's an SMS to the network, for response logging.
int Sms::send_message(const std::string& uri, const struct uri* route,
                      const std::string& hdrs, const char* ctype,
                      const uint8_t* body, size_t len, void* arg) {
    return sip_requestf(NULL, sip_, true, "MESSAGE", uri.c_str(), route, NULL,
                        NULL, response_handler, arg,
                        "%s"
                        "Call-ID: %x%x\r\n"
                        "CSeq: 1 MESSAGE\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %zu\r\n"
                        "\r\n"
                        "%b",
                        hdrs.c_str(), rand_u32(), rand_u32(), ctype, len, body,
                        len);
}

// TS 24.341 5.3.2.4: the SMS-layer ack is a new MESSAGE back to whoever sent
// the SMS (the SMSC/IP-SM-GW), routed like any other request from us.
void Sms::send_ack(const struct sip_msg* msg, sms::Format f,
                   const std::vector<uint8_t>& body) {
    const std::string to = pl_str(msg->from.auri);

    struct uri route;
    struct pl pl;
    pl_set_str(&pl, cfg_.outbound.c_str());
    if (uri_decode(&route, &pl)) {
        warning("sms: bad P-CSCF URI %s\n", cfg_.outbound.c_str());
        return;
    }

    const std::string hdrs = "To: <" + to + ">\r\nFrom: <" + cfg_.impu +
                             ">;tag=" + std::to_string(rand_u32()) + "\r\n" +
                             ims_headers() + "In-Reply-To: " +
                             pl_str(msg->callid) + "\r\n";
    int err = send_message(to, &route, hdrs, sms::format_mime(f), body.data(),
                           body.size(), NULL);
    if (err) warning("sms: cannot send ack to %s: %m\n", to.c_str(), err);
}

void Sms::response_handler(int err, const struct sip_msg* msg, void* arg) {
    const char* what = arg ? "SMS" : "ack/relay";

    if (err)
        warning("sms: %s failed: %m\n", what, err);
    else if (msg && msg->scode >= 300)
        warning("sms: %s rejected: %u %r\n", what, msg->scode, &msg->reason);
    else if (msg && msg->scode >= 200)
        info("sms: %s accepted (%u %r)\n", what, msg->scode, &msg->reason);
}

const struct cmd* Sms::cmd_table() {
    static const struct cmd cmds[] = {
        {"sms", 0, CMD_PRM,
         "Send SMS: sms <number> <text>, or sms <data URI> (tx binary_b64)",
         cmd_handler},
    };
    return cmds;
}

// "sms <number> <text>", or "sms <data URI>" with tx binary_b64
int Sms::cmd_handler(struct re_printf* pf, void* arg) {
    const struct cmd_arg* carg = static_cast<const struct cmd_arg*>(arg);
    Sms* self = instance_;
    const std::string prm = carg->prm ? carg->prm : "";
    std::string why;
    bool ok;

    if (!self) return ENOENT;

    if (self->cfg_.tx == SmsConfig::BinaryB64) {
        ok = self->send_data_uri(prm, why);
    } else {
        const size_t sp = prm.find(' ');
        if (sp == std::string::npos)
            return re_hprintf(pf, "usage: sms <number> <text>\n"), EINVAL;
        ok = self->send_text(prm.substr(0, sp), prm.substr(sp + 1), why);
    }

    if (!ok) {
        re_hprintf(pf, "sms: not sent: %s\n", why.c_str());
        return EINVAL;
    }
    return re_hprintf(pf, "sms: sending\n");
}

// LABEL: in-place sip_msg rewrite
//
// baresip has no way to deliver a MESSAGE except from its own SIP listener,
// which only takes text/plain and application/json. So the parsed request
// that libre hands every listener in turn is changed in place, new body,
// Content-Type and From.
void Sms::rewrite(const struct sip_msg* cmsg, const std::string& body,
                  const std::string& from) {
    // Allocated mutable by libre, only passed to listeners as const
    struct sip_msg* msg = const_cast<struct sip_msg*>(cmsg);

    struct mbuf* mb = mbuf_alloc(body.size() + 1);
    if (!mb) return;
    (void)mbuf_write_mem(mb, reinterpret_cast<const uint8_t*>(body.data()),
                         body.size());
    mb->pos = 0;

    held_.push_back(Held());
    Held& h = held_.back();
    h.msg = static_cast<struct sip_msg*>(mem_ref(msg));
    h.old_mb = msg->mb;  // takes over the request's reference
    h.from = from;

    msg->mb = mb;  // freed by the request's destructor
    pl_set_str(&msg->ctyp.type, "text");
    pl_set_str(&msg->ctyp.subtype, "plain");
    msg->ctyp.params = pl_null;
    if (!h.from.empty()) pl_set_str(&msg->from.auri, h.from.c_str());

    if (!tmr_isrunning(&gc_tmr_))
        tmr_start(&gc_tmr_, kGcIntervalMs, gc_handler, this);
}

void Sms::gc_handler(void* arg) { static_cast<Sms*>(arg)->gc(); }

void Sms::gc() {
    for (std::list<Held>::iterator it = held_.begin(); it != held_.end();) {
        if (mem_nrefs(it->msg) > 1) {
            ++it;
            continue;
        }
        mem_deref(it->msg);  // frees the new body too
        mem_deref(it->old_mb);
        it = held_.erase(it);
    }

    if (!held_.empty())
        tmr_start(&gc_tmr_, kGcIntervalMs, gc_handler, this);
}

bool Sms::seen(const std::string& id) {
    const uint64_t now = tmr_jiffies();

    while (!seen_.empty() &&
           (now - seen_.front().second > kSeenMs || seen_.size() > kSeenMax))
        seen_.pop_front();

    for (std::list<std::pair<std::string, uint64_t> >::iterator it =
             seen_.begin();
         it != seen_.end(); ++it)
        if (it->first == id) return true;

    seen_.push_back(std::make_pair(id, now));
    return false;
}

}  // namespace nekoims
