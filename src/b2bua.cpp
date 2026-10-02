// Despite the similar name and features, this is not the baresip-apps b2bua module. 
// It is a better implementation of the same idea though! Basically acts as a server,
// letting you use NekoIMS as an SIP proxy or trunk with your existing SIP client.

#include "b2bua.h"

#include <cstring>

namespace nekoims {

namespace {

const char* const kRealm = "nekoims";
const char* const kLanHost = "nekoims.invalid";  // LAN account AOR host
const uint32_t kDefaultExpires = 3600;           // seconds
const uint32_t kMaxExpires = 3600;
const uint64_t kAnswerRetryMs = 100;  // waiting for PRACK, see on_event()
const unsigned kAnswerRetries = 50;

std::string pl_str(const struct pl& pl) {
    return pl_isset(&pl) ? std::string(pl.p, pl.l) : std::string();
}

std::string uri_user(const char* uri) {
    struct pl pl;
    struct uri u;
    pl_set_str(&pl, uri ? uri : "");
    if (uri_decode(&u, &pl)) return std::string();
    return pl_str(u.user);
}

// Status codes worth passing on to the other leg; anything else becomes a
// plain hangup. A 401/407 from one side means nothing to the other.
uint16_t relay_scode(uint16_t scode) {
    if (scode < 300) return 0;
    if (scode == 401 || scode == 407) return 403;
    return scode;
}

// Reason phrase from a CLOSED event's text ("486 Busy Here"), if it is for
// scode. call_hangup() would otherwise say "Busy Here" for everything.
std::string relay_reason(uint16_t scode, const char* text) {
    char code[8];
    re_snprintf(code, sizeof(code), "%u ", scode);
    if (!text || std::strncmp(text, code, std::strlen(code))) return "";
    return text + std::strlen(code);
}

const char* reject_reason(uint16_t scode) {
    switch (scode) {
        case 404:
            return "Not Found";
        case 480:
            return "Temporarily Unavailable";
        default:
            return "Server Error";
    }
}

}  // namespace

B2bua::B2bua(const B2buaConfig& cfg, struct ua* ims_ua)
    : cfg_(cfg), ims_ua_(ims_ua) {}

B2bua::~B2bua() {
    if (bevent_) bevent_unregister(event_handler);
    mem_deref(lsnr_);

    // Calls belong to their UAs and are closed by ua_stop_all()
    for (std::list<Session>::iterator it = sessions_.begin();
         it != sessions_.end(); ++it)
        tmr_cancel(&it->tmr);
}

int B2bua::start() {
    // catchall: every INVITE the IMS account doesn't match lands here
    std::string aor = "<sip:" + cfg_.username + "@" + kLanHost + ">" +
                      ";regint=0;catchall=yes;answermode=manual" +
                      ";audio_codecs=" + cfg_.audio_codecs;

    int err = ua_alloc(&lan_ua_, aor.c_str());
    if (err) {
        warning("b2bua: LAN account setup failed: %m\n", err);
        return err;
    }

    // After baresip's own listener, which leaves REGISTER alone
    err = sip_listen(&lsnr_, uag_sip(), true, request_handler, this);
    if (err) return err;

    err = bevent_register(event_handler, this);
    if (err) return err;
    bevent_ = true;

    if (cfg_.password.empty())
        warning(
            "b2bua: no password set, anyone who can reach the SIP port can "
            "call through this line\n");

    info("b2bua: ready, LAN account %s (%s)\n", cfg_.username.c_str(),
         cfg_.audio_codecs.c_str());

    return 0;
}

void B2bua::event_handler(enum bevent_ev ev, struct bevent* event,
                          void* arg) {
    static_cast<B2bua*>(arg)->on_event(ev, event);
}

bool B2bua::request_handler(const struct sip_msg* msg, void* arg) {
    if (pl_strcmp(&msg->met, "REGISTER")) return false;

    static_cast<B2bua*>(arg)->on_register(msg);
    return true;
}

int B2bua::ha1_handler(uint8_t* ha1, const struct pl* user, const char* realm,
                       void* arg) {
    B2bua* self = static_cast<B2bua*>(arg);

    if (pl_strcmp(user, self->cfg_.username.c_str())) return EAUTH;

    return md5_printf(ha1, "%r:%s:%s", user, realm,
                      self->cfg_.password.c_str());
}

void B2bua::on_event(enum bevent_ev ev, struct bevent* event) {
    // call_accept is off in B2BUA mode, so new INVITEs are ours to accept
    if (ev == BEVENT_SIPSESS_CONN) {
        on_connect(bevent_get_msg(event));
        bevent_stop(event);
        return;
    }

    struct call* call = bevent_get_call(event);
    if (!call) return;

    if (ev == BEVENT_CALL_INCOMING) {
        new_session(call_get_ua(call), call);
        return;
    }

    std::list<Session>::iterator it = find(call);
    if (it == sessions_.end()) return;
    Session& s = *it;
    struct call* other = call == s.in ? s.out : s.in;
    int err = 0;

    switch (ev) {
        case BEVENT_CALL_PROGRESS:
            // Early media (ringback, announcements) toward the caller
            if (call == s.out && call_state(s.in) == CALL_STATE_INCOMING)
                err = call_progress(s.in);
            if (err) warning("b2bua: early media relay failed: %m\n", err);
            break;

        case BEVENT_CALL_ESTABLISHED:
            // Via the timer, like rejects, to stay out of this event
            if (call != s.out) break;
            s.answer_tries = 0;
            tmr_start(&s.tmr, 0, answer_handler, &s);
            break;

        case BEVENT_CALL_CLOSED:
            close_session(it, call, bevent_get_text(event));
            break;

        case BEVENT_CALL_DTMF_START: {
            const char* key = bevent_get_text(event);
            if (other && key && key[0]) call_send_digit(other, key[0]);
            break;
        }

        case BEVENT_CALL_DTMF_END:
            if (other) call_send_digit(other, KEYCODE_REL);
            break;

        default:
            break;
    }
}

void B2bua::on_connect(const struct sip_msg* msg) {
    struct ua* ua = uag_find_msg(msg);

    if (ua == lan_ua_ && !authorized(msg)) return;

    // ua_accept() replies 500 itself on failure
    int err = ua_accept(ua, msg);
    if (err) warning("b2bua: cannot accept call: %m\n", err);
}

// One binding is kept: the most recent REGISTER wins.
void B2bua::on_register(const struct sip_msg* msg) {
    if (!authorized(msg)) return;

    const struct sip_hdr* hdr = sip_msg_hdr(msg, SIP_HDR_CONTACT);
    if (hdr) {
        uint32_t expires = pl_isset(&msg->expires) ? pl_u32(&msg->expires)
                                                   : kDefaultExpires;
        std::string contact;

        if (pl_strcmp(&hdr->val, "*")) {
            struct sip_addr addr;
            struct pl pl;

            if (sip_addr_decode(&addr, &hdr->val)) {
                (void)sip_treply(NULL, uag_sip(), msg, 400, "Bad Contact");
                return;
            }
            if (!msg_param_decode(&addr.params, "expires", &pl))
                expires = pl_u32(&pl);
            contact = pl_str(addr.auri);
        } else {
            expires = 0;
        }

        if (expires > kMaxExpires) expires = kMaxExpires;

        if (expires) {
            if (contact != binding_)
                info("b2bua: %s registered from %J\n", contact.c_str(),
                     &msg->src);
            binding_ = contact;
            binding_expires_ = tmr_jiffies() + expires * 1000ULL;
        } else if (!binding_.empty()) {
            info("b2bua: %s unregistered\n", binding_.c_str());
            binding_.clear();
        }
    }

    const uint64_t now = tmr_jiffies();
    if (binding_.empty() || now >= binding_expires_) {
        (void)sip_treplyf(NULL, NULL, uag_sip(), msg, false, 200, "OK",
                          "Content-Length: 0\r\n\r\n");
        return;
    }

    const unsigned left = (unsigned)((binding_expires_ - now) / 1000);
    (void)sip_treplyf(NULL, NULL, uag_sip(), msg, false, 200, "OK",
                      "Contact: <%s>;expires=%u\r\n"
                      "Content-Length: 0\r\n\r\n",
                      binding_.c_str(), left);
}

// Digest auth for requests from the external UA. Replies 401/403 itself.
bool B2bua::authorized(const struct sip_msg* msg) {
    if (cfg_.password.empty()) return true;

    struct sip_uas_auth auth;
    std::memset(&auth, 0, sizeof(auth));
    auth.realm = kRealm;

    int err = sip_uas_auth_check(&auth, msg, ha1_handler, this);
    if (!err) return true;

    if (err == EAUTH) {
        struct sip_uas_auth* chal = NULL;
        if (sip_uas_auth_gen(&chal, msg, kRealm)) {
            (void)sip_treply(NULL, uag_sip(), msg, 500, "Server Error");
            return false;
        }
        (void)sip_treplyf(NULL, NULL, uag_sip(), msg, false, 401,
                          "Unauthorized", "%HContent-Length: 0\r\n\r\n",
                          sip_uas_auth_print, chal);
        mem_deref(chal);
        return false;
    }

    info("b2bua: %r from %J rejected, bad credentials\n", &msg->met,
         &msg->src);
    (void)sip_treply(NULL, uag_sip(), msg, 403, "Forbidden");
    return false;
}

void B2bua::new_session(struct ua* ua, struct call* call) {
    if (ua != lan_ua_ && ua != ims_ua_) return;

    sessions_.push_back(Session());
    Session& s = sessions_.back();
    s.owner = this;
    s.ua_in = ua;
    s.in = call;
    s.ua_out = nullptr;
    s.out = nullptr;
    s.scode = 0;
    s.answer_tries = 0;
    tmr_init(&s.tmr);

    std::string from, to;
    if (ua == lan_ua_) {
        // Toward IMS: From is the IMPU (account default)
        const std::string user = uri_user(call_localuri(call));
        if (user.empty()) {
            s.scode = 404;
        } else {
            s.ua_out = ims_ua_;
            to = "sip:" + user + "@" + cfg_.ims_domain;
        }
    } else {
        // Toward the external UA, showing the IMS caller as From
        to = lan_target();
        if (to.empty()) {
            info("b2bua: no registered UA or target, rejecting call\n");
            s.scode = 480;
        } else {
            s.ua_out = lan_ua_;
            from = call_peeruri(call);
            if (!from.compare(0, 4, "tel:"))
                from = "sip:" + from.substr(4, from.find(';') - 4) + "@" +
                       cfg_.ims_domain;
        }
    }

    if (s.ua_out) {
        int err = ua_connect(s.ua_out, &s.out,
                             from.empty() ? NULL : from.c_str(), to.c_str(),
                             VIDMODE_OFF);
        if (err) {
            warning("b2bua: cannot call %s: %m\n", to.c_str(), err);
            s.scode = 500;
        }
    }

    // This runs inside the incoming call's own event, where it can't be
    // freed yet, so rejects go through a timer.
    if (!s.out) {
        tmr_start(&s.tmr, 0, reject_handler, &s);
        return;
    }

    info("b2bua: %s -> %s\n", call_peeruri(call), to.c_str());

    // Cross-connect the legs: what one plays, the other sends
    char a[64], b[64];
    re_snprintf(a, sizeof(a), "A-%p", &s);
    re_snprintf(b, sizeof(b), "B-%p", &s);
    audio_set_devicename(call_audio(s.in), a, b);
    audio_set_devicename(call_audio(s.out), b, a);
}

void B2bua::reject_handler(void* arg) {
    Session* s = static_cast<Session*>(arg);
    B2bua* self = s->owner;
    struct ua* ua = s->ua_in;
    struct call* call = s->in;
    const uint16_t scode = s->scode;

    self->sessions_.erase(self->find(call));
    ua_hangup(ua, call, scode, reject_reason(scode));
}

// Answering the caller can be refused while it still owes us a PRACK for
// the early media 183, so keep retrying for a few seconds.
void B2bua::answer_handler(void* arg) {
    Session* s = static_cast<Session*>(arg);

    int err = call_answer(s->in, 200, VIDMODE_OFF);
    if (err == EAGAIN && ++s->answer_tries < kAnswerRetries) {
        tmr_start(&s->tmr, kAnswerRetryMs, answer_handler, s);
        return;
    }
    if (err) {
        B2bua* self = s->owner;
        struct ua* ua = s->ua_in;
        struct call* call = s->in;

        warning("b2bua: cannot answer caller: %m\n", err);
        self->close_session(self->find(call), call, NULL);  // hangs up out
        ua_hangup(ua, call, 500, reject_reason(500));
    }
}

void B2bua::close_session(std::list<Session>::iterator it,
                          struct call* closed, const char* text) {
    tmr_cancel(&it->tmr);

    const bool in = closed == it->in;
    struct ua* ua = in ? it->ua_out : it->ua_in;
    struct call* other = in ? it->out : it->in;
    sessions_.erase(it);

    // ua_hangup() emits CLOSED for the other leg too; it's already gone
    // from sessions_ by then.
    if (!other) return;

    const uint16_t scode = relay_scode(call_scode(closed));
    const std::string reason = relay_reason(scode, text);
    ua_hangup(ua, other, scode, reason.empty() ? NULL : reason.c_str());
}

std::list<B2bua::Session>::iterator B2bua::find(const struct call* call) {
    for (std::list<Session>::iterator it = sessions_.begin();
         it != sessions_.end(); ++it)
        if (it->in == call || it->out == call) return it;
    return sessions_.end();
}

std::string B2bua::lan_target() {
    if (!binding_.empty() && tmr_jiffies() < binding_expires_)
        return binding_;
    return cfg_.target;
}

}  // namespace nekoims
