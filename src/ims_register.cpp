#include "ims_register.h"

#include <cstring>

#include <baresip.h>

namespace nekoims {

namespace {

const uint32_t kMinRefresh = 30;  // seconds
const uint32_t kRetryBase = 30;   // seconds, doubled per failure
const uint32_t kRetryMax = 600;
const uint64_t kStopTimeoutMs = 8000;
const unsigned kMaxAuthFailures = 2;

std::string pl_str(const struct pl& pl) {
    return pl_isset(&pl) ? std::string(pl.p, pl.l) : std::string();
}

std::string hex(const uint8_t* p, size_t n) {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s += digits[p[i] >> 4];
        s += digits[p[i] & 0xf];
    }
    return s;
}

std::string b64(const std::vector<uint8_t>& in) {
    std::vector<char> out(in.size() * 4 / 3 + 4);
    size_t olen = out.size();
    if (base64_encode(in.data(), in.size(), out.data(), &olen))
        return std::string();
    return std::string(out.data(), olen);
}

void hmac_md5(const std::vector<uint8_t>& key, const char* msg,
              uint8_t out[MD5_SIZE]) {
    uint8_t k[64] = {0};
    if (key.size() > sizeof(k))
        md5(key.data(), key.size(), k);
    else
        std::memcpy(k, key.data(), key.size());

    std::vector<uint8_t> buf(64 + std::strlen(msg));
    for (size_t i = 0; i < 64; ++i) buf[i] = k[i] ^ 0x36;
    std::memcpy(&buf[64], msg, std::strlen(msg));
    uint8_t inner[MD5_SIZE];
    md5(buf.data(), buf.size(), inner);

    uint8_t outer[64 + MD5_SIZE];
    for (size_t i = 0; i < 64; ++i) outer[i] = k[i] ^ 0x5c;
    std::memcpy(&outer[64], inner, MD5_SIZE);
    md5(outer, sizeof(outer), out);
}

// Does a quoted qop-options list contain "auth" (not just auth-int)?
bool qop_has_auth(const struct pl& qop) {
    const std::string s = pl_str(qop);
    size_t pos = 0;
    while (pos < s.size()) {
        size_t end = s.find(',', pos);
        if (end == std::string::npos) end = s.size();
        std::string tok = s.substr(pos, end - pos);
        tok.erase(0, tok.find_first_not_of(" \t\""));
        tok.erase(tok.find_last_not_of(" \t\"") + 1);
        if (tok == "auth") return true;
        pos = end + 1;
    }
    return false;
}

}  // namespace

struct ImsRegistration::AkaJob {
    ImsRegistration* self;
    SimcardClient sim;
    Challenge ch;
    std::vector<uint8_t> rand, autn;
    AkaResult result;

    AkaJob(ImsRegistration* s, const SimcardClient& c) : self(s), sim(c) {}
};

ImsRegistration::ImsRegistration(struct sip* sip, const ImsRegConfig& cfg,
                                 const SimcardClient& sim)
    : sip_(sip), cfg_(cfg), sim_(sim), expires_(cfg.expires) {
    tmr_init(&tmr_);
    tmr_init(&stop_tmr_);
}

ImsRegistration::~ImsRegistration() {
    tmr_cancel(&tmr_);
    tmr_cancel(&stop_tmr_);
    if (job_) job_->self = nullptr;  // freed by aka_done
    mem_deref(req_);
    mem_deref(dlg_);
}

int ImsRegistration::start() {
    const std::string uri = "sip:" + cfg_.domain;
    const char* routev[1] = {cfg_.outbound.c_str()};

    int err = sip_dialog_alloc(&dlg_, uri.c_str(), cfg_.impu.c_str(), NULL,
                               cfg_.impu.c_str(), routev, 1);
    if (err) return err;

    info("ims: registering %s (impi %s) via %s\n", cfg_.impu.c_str(),
         cfg_.impi.c_str(), cfg_.outbound.c_str());

    return send_register(empty_authorization());
}

void ImsRegistration::stop(DoneHandler done, void* arg) {
    done_ = done;
    done_arg_ = arg;
    stopping_ = true;
    tmr_cancel(&tmr_);

    if (job_) {
        job_->self = nullptr;
        job_ = nullptr;
    }

    if (!registered_ || !dlg_) {
        finish_stop();
        return;
    }

    info("ims: deregistering\n");
    tmr_start(&stop_tmr_, kStopTimeoutMs, stop_timeout_handler, this);

    expires_ = 0;
    if (send_register(empty_authorization())) finish_stop();
}

void ImsRegistration::finish_stop() {
    tmr_cancel(&stop_tmr_);
    req_ = static_cast<struct sip_request*>(mem_deref(req_));
    registered_ = false;

    DoneHandler done = done_;
    done_ = nullptr;
    if (done) done(done_arg_);
}

void ImsRegistration::stop_timeout_handler(void* arg) {
    ImsRegistration* self = static_cast<ImsRegistration*>(arg);
    warning("ims: deregistration timed out\n");
    self->finish_stop();
}

// TS 24.229 5.1.1.2.1: initial REGISTER carries the IMPI with empty nonce and
// response so the network can pick the right user record.
std::string ImsRegistration::empty_authorization() const {
    return "Authorization: Digest username=\"" + cfg_.impi + "\",realm=\"" +
           cfg_.domain + "\",uri=\"sip:" + cfg_.domain +
           "\",nonce=\"\",response=\"\"\r\n";
}

int ImsRegistration::send_register(const std::string& authorization) {
    std::string hdrs = authorization;
    for (size_t i = 0; i < cfg_.headers.size(); ++i)
        hdrs += cfg_.headers[i].first + ": " + cfg_.headers[i].second + "\r\n";

    req_ = static_cast<struct sip_request*>(mem_deref(req_));

    return sip_drequestf(&req_, sip_, true, "REGISTER", dlg_, 0, NULL,
                         send_handler, response_handler, this,
                         "%s"
                         "Supported: path\r\n"
                         "Expires: %u\r\n"
                         "Content-Length: 0\r\n"
                         "\r\n",
                         hdrs.c_str(), expires_);
}

int ImsRegistration::send_handler(enum sip_transp tp, struct sa* src,
                                  const struct sa* dst, struct mbuf* mb,
                                  struct mbuf** contp, void* arg) {
    ImsRegistration* self = static_cast<ImsRegistration*>(arg);
    (void)dst;
    (void)contp;

    return mbuf_printf(mb, "Contact: <sip:%s@%J%s>%s\r\n",
                       self->cfg_.contact_user.c_str(), src,
                       sip_transp_param(tp), self->cfg_.contact_params.c_str());
}

void ImsRegistration::response_handler(int err, const struct sip_msg* msg,
                                       void* arg) {
    static_cast<ImsRegistration*>(arg)->on_response(err, msg);
}

void ImsRegistration::on_response(int err, const struct sip_msg* msg) {
    if (err || !msg) {
        fail(err ? "transport error" : "no response");
        if (err) warning("ims: REGISTER failed: %m\n", err);
        return;
    }

    if (msg->scode < 200) return;

    if (msg->scode < 300) {
        on_ok(msg);
        return;
    }

    if (msg->scode == 401) {
        if (sent_credentials_ && ++auth_failures_ >= kMaxAuthFailures) {
            fail("credentials rejected");
            return;
        }
        on_challenge(msg);
        return;
    }

    if (msg->scode == 423) {
        const struct sip_hdr* minexp = sip_msg_hdr(msg, SIP_HDR_MIN_EXPIRES);
        if (minexp && pl_u32(&minexp->val) && expires_) {
            expires_ = pl_u32(&minexp->val);
            sent_credentials_ = false;
            if (!send_register(empty_authorization())) return;
        }
    }

    warning("ims: REGISTER rejected: %u %r\n", msg->scode, &msg->reason);
    fail("rejected");
}

void ImsRegistration::on_ok(const struct sip_msg* msg) {
    sent_credentials_ = false;
    auth_failures_ = 0;
    retry_count_ = 0;

    if (stopping_) {
        info("ims: deregistered\n");
        finish_stop();
        return;
    }

    service_route_.clear();
    struct le* le;
    for (le = list_head(&msg->hdrl); le; le = le->next) {
        const struct sip_hdr* hdr =
            static_cast<const struct sip_hdr*>(le->data);
        if (hdr->id == SIP_HDR_SERVICE_ROUTE)
            service_route_.push_back(pl_str(hdr->val));
        else if (!pl_strcasecmp(&hdr->name, "P-Associated-URI"))
            info("ims: P-Associated-URI: %r\n", &hdr->val);
    }

    const uint32_t granted = granted_expires(msg);
    registered_ = true;

    info("ims: REGISTERED (%u %r), expires %u s\n", msg->scode, &msg->reason,
         granted);
    for (size_t i = 0; i < service_route_.size(); ++i)
        info("ims: Service-Route: %s\n", service_route_[i].c_str());

    uint32_t refresh = granted / 2;
    if (refresh < kMinRefresh) refresh = kMinRefresh;
    tmr_start(&tmr_, refresh * 1000ULL, timer_handler, this);
}

// Expiry granted for our binding: Contact expires= wins over Expires.
uint32_t ImsRegistration::granted_expires(const struct sip_msg* msg) const {
    struct le* le;
    for (le = list_head(&msg->hdrl); le; le = le->next) {
        const struct sip_hdr* hdr =
            static_cast<const struct sip_hdr*>(le->data);
        struct sip_addr addr;
        struct pl pl;

        if (hdr->id != SIP_HDR_CONTACT || sip_addr_decode(&addr, &hdr->val))
            continue;
        if (pl_strcmp(&addr.uri.user, cfg_.contact_user.c_str())) continue;
        if (!msg_param_decode(&addr.params, "expires", &pl)) return pl_u32(&pl);
    }

    const struct sip_hdr* exp = sip_msg_hdr(msg, SIP_HDR_EXPIRES);
    if (exp) return pl_u32(&exp->val);

    return expires_;
}

void ImsRegistration::on_challenge(const struct sip_msg* msg) {
    const struct sip_hdr* hdr = sip_msg_hdr(msg, SIP_HDR_WWW_AUTHENTICATE);
    struct httpauth_digest_chall hc;

    if (!hdr || httpauth_digest_challenge_decode(&hc, &hdr->val)) {
        fail("401 without a usable WWW-Authenticate");
        return;
    }

    Challenge ch;
    ch.realm = pl_str(hc.realm);
    ch.nonce = pl_str(hc.nonce);
    ch.opaque = pl_str(hc.opaque);
    ch.algorithm = pl_isset(&hc.algorithm) ? pl_str(hc.algorithm) : "MD5";
    ch.qop_auth = qop_has_auth(hc.qop);

    if (str_casecmp(ch.algorithm.c_str(), "AKAv1-MD5") &&
        str_casecmp(ch.algorithm.c_str(), "AKAv2-MD5")) {
        warning("ims: unsupported auth algorithm %s\n", ch.algorithm.c_str());
        fail("unsupported algorithm");
        return;
    }

    // RFC 3310 3.2: nonce = base64(RAND || AUTN || server data)
    uint8_t raw[256];
    size_t rawlen = sizeof(raw);
    if (base64_decode(ch.nonce.data(), ch.nonce.size(), raw, &rawlen) ||
        rawlen < 32) {
        fail("malformed AKA nonce");
        return;
    }

    AkaJob* job = new AkaJob(this, sim_);
    job->ch = ch;
    job->rand.assign(raw, raw + 16);
    job->autn.assign(raw + 16, raw + 32);

    if (job_) job_->self = nullptr;
    job_ = job;

    int err = re_thread_async(aka_work, aka_done, job);
    if (err) {
        job_ = nullptr;
        delete job;
        warning("ims: cannot start AKA worker: %m\n", err);
        fail("AKA worker");
    }
}

int ImsRegistration::aka_work(void* arg) {
    AkaJob* job = static_cast<AkaJob*>(arg);
    job->result = job->sim.authenticate(job->rand, job->autn);
    return 0;
}

void ImsRegistration::aka_done(int err, void* arg) {
    AkaJob* job = static_cast<AkaJob*>(arg);

    if (job->self && job->self->job_ == job) {
        job->self->job_ = nullptr;
        if (err) {
            job->result.ok = false;
            job->result.sync_failure = false;
            job->result.error = "worker failed";
        }
        job->self->on_aka(job);
    }

    delete job;
}

void ImsRegistration::on_aka(AkaJob* job) {
    const Challenge& ch = job->ch;
    const AkaResult& r = job->result;
    std::vector<uint8_t> password;
    std::string auts;

    if (r.sync_failure) {
        // RFC 3310 3.4: empty password, AUTS lets the HSS resync SQN
        warning("ims: AKA synchronisation failure, sending AUTS\n");
        auts = b64(r.auts);
    } else if (!r.ok) {
        warning("ims: AKA failed: %s\n", r.error.c_str());
        fail("AKA");
        return;
    } else if (!str_casecmp(ch.algorithm.c_str(), "AKAv2-MD5")) {
        // RFC 4169: password = base64(PRF(RES||IK||CK,
        // "http-digest-akav2-password"))
        std::vector<uint8_t> key(r.res);
        key.insert(key.end(), r.ik.begin(), r.ik.end());
        key.insert(key.end(), r.ck.begin(), r.ck.end());
        uint8_t prf[MD5_SIZE];
        hmac_md5(key, "http-digest-akav2-password", prf);
        const std::string s = b64(std::vector<uint8_t>(prf, prf + MD5_SIZE));
        password.assign(s.begin(), s.end());
    } else {
        password = r.res;  // RFC 3310: password = RES
    }

    const std::string uri = "sip:" + cfg_.domain;
    const std::string nc = "00000001";
    char cnonce[17];
    re_snprintf(cnonce, sizeof(cnonce), "%016llx",
                (unsigned long long)rand_u64());

    uint8_t ha1[MD5_SIZE], ha2[MD5_SIZE], resp[MD5_SIZE];
    int err = md5_printf(
        ha1, "%s:%s:%b", cfg_.impi.c_str(), ch.realm.c_str(),
        password.empty() ? "" : reinterpret_cast<const char*>(password.data()),
        password.size());
    err |= md5_printf(ha2, "REGISTER:%s", uri.c_str());
    if (ch.qop_auth)
        err |=
            md5_printf(resp, "%w:%s:%s:%s:auth:%w", ha1, sizeof(ha1),
                       ch.nonce.c_str(), nc.c_str(), cnonce, ha2, sizeof(ha2));
    else
        err |= md5_printf(resp, "%w:%s:%w", ha1, sizeof(ha1), ch.nonce.c_str(),
                          ha2, sizeof(ha2));
    if (err) {
        fail("digest");
        return;
    }

    std::string auth = "Authorization: Digest username=\"" + cfg_.impi +
                       "\",realm=\"" + ch.realm + "\",nonce=\"" + ch.nonce +
                       "\",uri=\"" + uri + "\",response=\"" +
                       hex(resp, sizeof(resp)) + "\",algorithm=" + ch.algorithm;
    if (ch.qop_auth)
        auth += ",qop=auth,nc=" + nc + ",cnonce=\"" + cnonce + "\"";
    if (!ch.opaque.empty()) auth += ",opaque=\"" + ch.opaque + "\"";
    if (!auts.empty()) auth += ",auts=\"" + auts + "\"";
    auth += "\r\n";

    // A resync isn't a credential failure; the next 401 carries a new vector.
    sent_credentials_ = !r.sync_failure;

    err = send_register(auth);
    if (err) {
        warning("ims: sending REGISTER failed: %m\n", err);
        fail("send");
    }
}

void ImsRegistration::fail(const char* why) {
    registered_ = false;
    sent_credentials_ = false;
    auth_failures_ = 0;

    if (stopping_) {
        finish_stop();
        return;
    }

    uint32_t delay = kRetryBase << (retry_count_ < 5 ? retry_count_ : 5);
    if (delay > kRetryMax) delay = kRetryMax;
    ++retry_count_;

    warning("ims: registration failed (%s), retrying in %u s\n", why, delay);
    tmr_start(&tmr_, delay * 1000ULL, timer_handler, this);
}

void ImsRegistration::timer_handler(void* arg) {
    ImsRegistration* self = static_cast<ImsRegistration*>(arg);
    self->expires_ = self->cfg_.expires;

    int err = self->send_register(self->empty_authorization());
    if (err) {
        warning("ims: REGISTER send failed: %m\n", err);
        self->fail("send");
    }
}

}  // namespace nekoims
