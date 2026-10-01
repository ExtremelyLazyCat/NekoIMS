// Makes our BYEs look like a Verizon handset's (TS 24.229).
//
// Verizon handsets send Reason: SIP;cause=200;text="User Triggered" on
// hangup. Without it, a Google Pixel we hang up on keeps a stale call slot in
// its modem and rejects every later call from us until its IMS stack
// restarts. They also send P-Access-Network-Info and P-Preferred-Identity,
// which the network uses when releasing the session. It's still a mistrery 
// why this bug only affects Google Pixel phones, but we this also brings us
// closer to the iPhone VoWiFi behavior, which is a good thing.
//
// baresip doesn't expose a call's sipsess, so wrap libre's sipsess_bye() at
// link time (-Wl,--wrap=sipsess_bye) and set the close headers just before
// the BYE is built.

#include "bye_reason.h"

#include <re.h>

namespace {

std::string g_extra_hdrs;

}  // namespace

namespace nekoims {

void set_bye_headers(const std::string& hdrs) { g_extra_hdrs = hdrs; }

}  // namespace nekoims

extern "C" {

int __real_sipsess_bye(struct sipsess* sess, bool reset_ls);

int __wrap_sipsess_bye(struct sipsess* sess, bool reset_ls) {
    (void)sipsess_set_close_headers(
        sess, "Reason: SIP;cause=200;text=\"User Triggered\"\r\n%s",
        g_extra_hdrs.c_str());

    return __real_sipsess_bye(sess, reset_ls);
}

}  // extern "C"
