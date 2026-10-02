// SMS over IMS (TS 24.341) wire formats:
//
//   application/vnd.3gpp.sms   RP-DATA (TS 24.011) carrying an SMS-DELIVER
//                              or SMS-SUBMIT TPDU (TS 23.040), RP-ACK/ERROR
//   application/vnd.3gpp2.sms  C.S0015 SMS transport layer message, as sent
//                              by Verizon
//
// As for what's actually been tested for SURE technically only vnd.3gpp2.sms on 
// Verizon's network, but the vnd.3gpp.sms code is based on the 3GPP spec and should
// work. No pinkie promises though.

#ifndef NEKOIMS_SMS_CODEC_H
#define NEKOIMS_SMS_CODEC_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace nekoims {
namespace sms {

enum class Format { Unknown, Gpp, Gpp2 };

// From a Content-Type subtype ("vnd.3gpp.sms", "vnd.3gpp2.sms")
Format format_from_subtype(const std::string& subtype);
const char* format_mime(Format f);  // "application/vnd.3gpp2.sms"

struct Message {
    // Deliver: an SMS for us. Ack: the network's verdict on one we sent
    // (RP-ACK/RP-ERROR, 3GPP2 SMS Acknowledge), matched by ref.
    enum Kind { Deliver, Ack };

    Format format = Format::Unknown;
    Kind kind = Deliver;
    std::string sender;     // originator, E.164 with + when known
    std::string timestamp;  // service centre time, "YYYY-MM-DD hh:mm:ss"
    bool has_text = false;
    std::string text;  // UTF-8, one part of a concatenated SMS
    std::string id;    // for dropping network retransmissions
    std::vector<uint8_t> ack;  // SMS-layer ack body, empty if none wanted
    std::string smsc;  // 3GPP: service centre number from RP-OA

    // Kind Ack
    unsigned ref = 0;  // RP-MR or 3GPP2 REPLY_SEQ of the message we sent
    bool accepted = false;
    unsigned cause = 0;  // RP-Cause or 3GPP2 cause code when rejected
};

// False only if the envelope itself is malformed (nothing can be acked).
bool decode(Format f, const uint8_t* p, size_t n, Message& out);

// MO SMS to `to` (+E.164 or local digits), single part. ref is the RP-MR
// (3GPP) or REPLY_SEQ (3GPP2, 6 bits) the network acks with; msg_id is the
// 3GPP2 message identifier; smsc is the 3GPP service centre number (RP-DA).
bool encode_submit(Format f, const std::string& to, const std::string& text,
                   unsigned ref, unsigned msg_id, const std::string& smsc,
                   std::vector<uint8_t>& out, std::string& why);

// ref of an MO message, to match the network's ack; false if not one
bool submit_ref(Format f, const uint8_t* p, size_t n, unsigned& ref);

std::string base64(const uint8_t* p, size_t n);
bool unbase64(const std::string& in, std::vector<uint8_t>& out);

}  // namespace sms
}  // namespace nekoims

#endif
