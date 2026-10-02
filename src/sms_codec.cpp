// This file looks daunting because it's large, but it's mainly helper function after helper function.
// The function's you care about is decode_3gpp() and decode_3gpp2() which take a raw SMS message 
// and turn it into a Message struct as well as their encoding counterparts which do the opposite.
// The rest of the code is just helper functions for those two main functions.

#include "sms_codec.h"

#include <cstdio>

namespace nekoims {
namespace sms {

namespace {

// TS 23.038 6.2.1 default alphabet and extension table, as UTF-8
const char* const kGsm7[128] = {
    "@",  "\xc2\xa3", "$",  "\xc2\xa5", "\xc3\xa8", "\xc3\xa9", "\xc3\xb9",
    "\xc3\xac", "\xc3\xb2", "\xc3\x87", "\n", "\xc3\x98", "\xc3\xb8", "\r",
    "\xc3\x85", "\xc3\xa5", "\xce\x94", "_", "\xce\xa6", "\xce\x93",
    "\xce\x9b", "\xce\xa9", "\xce\xa0", "\xce\xa8", "\xce\xa3", "\xce\x98",
    "\xce\x9e", "",  // 0x1B escape, handled separately
    "\xc3\x86", "\xc3\xa6", "\xc3\x9f", "\xc3\x89", " ", "!", "\"", "#",
    "\xc2\xa4", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", "0",
    "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">",
    "?", "\xc2\xa1", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K",
    "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y",
    "Z", "\xc3\x84", "\xc3\x96", "\xc3\x91", "\xc3\x9c", "\xc2\xa7",
    "\xc2\xbf", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
    "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    "\xc3\xa4", "\xc3\xb6", "\xc3\xb1", "\xc3\xbc", "\xc3\xa0",
};

const char* gsm7_ext(uint8_t c) {
    switch (c) {
        case 0x0a: return "\n";  // page break
        case 0x14: return "^";
        case 0x28: return "{";
        case 0x29: return "}";
        case 0x2f: return "\\";
        case 0x3c: return "[";
        case 0x3d: return "~";
        case 0x3e: return "]";
        case 0x40: return "|";
        case 0x65: return "\xe2\x82\xac";  // euro
        default: return kGsm7[c];  // undefined: shown as the default char
    }
}

std::string gsm7_to_utf8(const std::vector<uint8_t>& septets) {
    std::string out;
    for (size_t i = 0; i < septets.size(); ++i) {
        if (septets[i] == 0x1b && i + 1 < septets.size())
            out += gsm7_ext(septets[++i]);
        else
            out += kGsm7[septets[i] & 0x7f];
    }
    return out;
}

// TS 23.038 6.1.2.1 packing: septets LSB first from start_bit
bool gsm7_unpack(const uint8_t* p, size_t n, size_t start_bit, size_t count,
                 std::vector<uint8_t>& out) {
    out.clear();
    for (size_t k = 0; k < count; ++k) {
        const size_t bit = start_bit + 7 * k;
        const size_t byte = bit / 8, shift = bit % 8;
        if (byte >= n) return false;
        unsigned v = p[byte] >> shift;
        if (shift > 1) {
            if (byte + 1 >= n) return false;
            v |= p[byte + 1] << (8 - shift);
        }
        out.push_back(v & 0x7f);
    }
    return true;
}

void put_utf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xc0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xe0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (cp & 0x3f));
    } else {
        out += static_cast<char>(0xf0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (cp & 0x3f));
    }
}

bool utf16be_to_utf8(const uint8_t* p, size_t n, std::string& out) {
    out.clear();
    if (n % 2) return false;
    for (size_t i = 0; i < n; i += 2) {
        uint32_t cp = (p[i] << 8) | p[i + 1];
        if (cp >= 0xd800 && cp < 0xdc00 && i + 3 < n) {
            const uint32_t lo = (p[i + 2] << 8) | p[i + 3];
            if (lo >= 0xdc00 && lo < 0xe000) {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                i += 2;
            }
        }
        put_utf8(out, cp);
    }
    return true;
}

bool utf8_decode(const std::string& in, std::vector<uint32_t>& out) {
    out.clear();
    for (size_t i = 0; i < in.size();) {
        const uint8_t c = in[i];
        size_t len;
        uint32_t cp;
        if (c < 0x80) {
            len = 1, cp = c;
        } else if ((c & 0xe0) == 0xc0) {
            len = 2, cp = c & 0x1f;
        } else if ((c & 0xf0) == 0xe0) {
            len = 3, cp = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {
            len = 4, cp = c & 0x07;
        } else {
            return false;
        }
        if (i + len > in.size()) return false;
        for (size_t k = 1; k < len; ++k) {
            if ((in[i + k] & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (in[i + k] & 0x3f);
        }
        out.push_back(cp);
        i += len;
    }
    return true;
}

// Septets for text in the GSM default alphabet (+ extension table), false
// if any character isn't in it.
bool gsm7_encode(const std::vector<uint32_t>& text, std::vector<uint8_t>& out) {
    static const uint8_t ext[] = {0x0a, 0x14, 0x28, 0x29, 0x2f,
                                  0x3c, 0x3d, 0x3e, 0x40, 0x65};
    out.clear();
    for (size_t i = 0; i < text.size(); ++i) {
        std::string ch;
        put_utf8(ch, text[i]);
        bool found = false;
        for (unsigned c = 0; c < 128 && !found; ++c) {
            if (c != 0x1b && ch == kGsm7[c]) {
                out.push_back(c);
                found = true;
            }
        }
        for (size_t k = 0; k < sizeof(ext) && !found; ++k) {
            if (ext[k] != 0x0a && ch == gsm7_ext(ext[k])) {
                out.push_back(0x1b);
                out.push_back(ext[k]);
                found = true;
            }
        }
        if (!found) return false;
    }
    return true;
}

void gsm7_pack(const std::vector<uint8_t>& septets, std::vector<uint8_t>& out) {
    out.assign((septets.size() * 7 + 7) / 8, 0);
    for (size_t k = 0; k < septets.size(); ++k) {
        const size_t bit = 7 * k, byte = bit / 8, shift = bit % 8;
        out[byte] |= septets[k] << shift;
        if (shift > 1) out[byte + 1] |= septets[k] >> (8 - shift);
    }
}

void utf16be(const std::vector<uint32_t>& text, std::vector<uint8_t>& out) {
    out.clear();
    for (size_t i = 0; i < text.size(); ++i) {
        uint32_t cp = text[i];
        if (cp >= 0x10000) {
            cp -= 0x10000;
            const uint32_t hi = 0xd800 + (cp >> 10), lo = 0xdc00 + (cp & 0x3ff);
            out.push_back(hi >> 8), out.push_back(hi & 0xff);
            out.push_back(lo >> 8), out.push_back(lo & 0xff);
        } else {
            out.push_back(cp >> 8), out.push_back(cp & 0xff);
        }
    }
}

// "+15551234567" -> international, digits; false unless digits (* # ok)
bool split_number(const std::string& in, bool& intl, std::string& digits) {
    intl = !in.empty() && in[0] == '+';
    digits = in.substr(intl ? 1 : 0);
    return !digits.empty() &&
           digits.find_first_not_of("0123456789*#") == std::string::npos;
}

// Semi-octets, low nibble first, F filler (TS 23.040 9.1.2.3)
void bcd_digits(const std::string& digits, std::vector<uint8_t>& out) {
    for (size_t i = 0; i < digits.size(); i += 2) {
        static const std::string map = "0123456789*#";
        const unsigned lo = map.find(digits[i]);
        const unsigned hi = i + 1 < digits.size() ? map.find(digits[i + 1]) : 0xf;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
}

std::string latin1_to_utf8(const uint8_t* p, size_t n) {
    std::string out;
    for (size_t i = 0; i < n; ++i) put_utf8(out, p[i]);
    return out;
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

std::string timestamp(const int v[6]) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d", v[0],
                  v[1], v[2], v[3], v[4], v[5]);
    return buf;
}

// C.S0015 fields are bit-packed MSB first, not byte aligned
class Bits {
   public:
    Bits(const uint8_t* p, size_t n) : p_(p), nbits_(n * 8) {}

    uint32_t get(unsigned n) {
        uint32_t v = 0;
        for (unsigned i = 0; i < n; ++i, ++pos_) {
            if (pos_ >= nbits_) {
                ok_ = false;
                return 0;
            }
            v = (v << 1) | ((p_[pos_ / 8] >> (7 - pos_ % 8)) & 1);
        }
        return v;
    }
    void skip(size_t n) { pos_ += n; }
    size_t left() const { return pos_ < nbits_ ? nbits_ - pos_ : 0; }
    bool ok() const { return ok_ && pos_ <= nbits_; }

   private:
    const uint8_t* p_;
    size_t nbits_;
    size_t pos_ = 0;
    bool ok_ = true;
};

/////////////////////////////////////////////////////////////////////////////
// 3GPP: RP-DATA (TS 24.011 7.3.1.1) / SMS-DELIVER (TS 23.040 9.2.2.1)

// TS 23.040 9.1.2.5 address, len in digits (semi-octets)
bool tp_address(const uint8_t* p, size_t n, size_t& used, std::string& out) {
    if (n < 2) return false;
    const unsigned digits = p[0], toa = p[1];
    const size_t nbytes = (digits + 1) / 2;
    if (2 + nbytes > n) return false;
    used = 2 + nbytes;

    out.clear();
    if (((toa >> 4) & 7) == 5) {  // alphanumeric, GSM 7-bit packed
        std::vector<uint8_t> sept;
        if (!gsm7_unpack(p + 2, nbytes, 0, digits * 4 / 7, sept))
            return false;
        out = gsm7_to_utf8(sept);
        return true;
    }

    static const char bcd[] = "0123456789*#abc";
    if (((toa >> 4) & 7) == 1) out += '+';
    for (unsigned i = 0; i < digits; ++i) {
        const unsigned d = (p[2 + i / 2] >> (i % 2 ? 4 : 0)) & 0xf;
        if (d == 0xf) break;
        out += bcd[d];
    }
    return true;
}

void decode_deliver(const uint8_t* t, size_t n, Message& out) {
    if (n < 1 || (t[0] & 3) != 0) return;  // not SMS-DELIVER
    const bool udhi = t[0] & 0x40;

    size_t used = 0;
    if (!tp_address(t + 1, n - 1, used, out.sender)) return;
    size_t j = 1 + used;
    if (j + 10 > n) return;

    const uint8_t dcs = t[j + 1];
    const uint8_t* scts = t + j + 2;
    const unsigned udl = t[j + 9];
    const uint8_t* ud = t + j + 10;
    const size_t ud_len = n - (j + 10);

    int ts[6];
    for (int i = 0; i < 6; ++i) ts[i] = (scts[i] & 0xf) * 10 + (scts[i] >> 4);
    ts[0] += 2000;
    out.timestamp = timestamp(ts);
    out.id = out.sender + "/" + hex(scts, 7);

    // TS 23.038 4: alphabet, -1 for anything without a text form
    int alphabet = -1;
    if ((dcs & 0x80) == 0) {
        if (!(dcs & 0x20)) alphabet = (dcs >> 2) & 3;  // not compressed
    } else if ((dcs & 0xf0) == 0xf0) {
        alphabet = (dcs & 4) ? 1 : 0;
    } else if ((dcs & 0xf0) == 0xc0 || (dcs & 0xf0) == 0xd0) {
        alphabet = 0;
    } else if ((dcs & 0xf0) == 0xe0) {
        alphabet = 2;
    }

    const size_t hdr = udhi ? (ud_len ? ud[0] + 1u : ud_len + 1) : 0;
    if (hdr > ud_len) return;

    if (alphabet == 0) {
        const size_t hdr_bits = hdr * 8;
        const size_t fill = (7 - hdr_bits % 7) % 7;
        const size_t skip = (hdr_bits + fill) / 7;
        if (skip > udl) return;
        std::vector<uint8_t> sept;
        if (!gsm7_unpack(ud, ud_len, hdr_bits + fill, udl - skip, sept))
            return;
        out.text = gsm7_to_utf8(sept);
        out.has_text = true;
    } else if (alphabet == 2) {
        if (udl > ud_len || hdr > udl) return;
        out.has_text = utf16be_to_utf8(ud + hdr, udl - hdr, out.text);
    }
}

// TS 24.011 8.2.5.1 RP address: length in octets, TOA, BCD
std::string rp_address(const uint8_t* p, size_t len) {
    if (len < 2) return std::string();
    static const char bcd[] = "0123456789*#abc";
    std::string out = ((p[0] >> 4) & 7) == 1 ? "+" : "";
    for (size_t i = 1; i < len; ++i) {
        for (int k = 0; k < 2; ++k) {
            const unsigned d = (p[i] >> (k ? 4 : 0)) & 0xf;
            if (d == 0xf) return out;
            out += bcd[d];
        }
    }
    return out;
}

bool decode_3gpp(const uint8_t* p, size_t n, Message& out) {
    if (n < 2) return false;
    const unsigned mti = p[0] & 7;
    const uint8_t mr = p[1];

    // RP-ACK / RP-ERROR network to MS: the verdict on one of ours
    if (mti == 3 || mti == 5) {
        out.kind = Message::Ack;
        out.ref = mr;
        out.accepted = mti == 3;
        if (mti == 5 && n >= 4 && p[2] >= 1) out.cause = p[3] & 0x7f;
        out.id = hex(p, n);
        return true;
    }
    if (mti != 1) return false;  // only RP-DATA network to MS is ours

    size_t i = 2;
    for (int k = 0; k < 2; ++k) {  // RP-OA (service centre), RP-DA (empty)
        if (i >= n || i + 1 + p[i] > n) return false;
        if (k == 0) out.smsc = rp_address(p + i + 1, p[i]);
        i += 1 + p[i];
    }
    if (i >= n || i + 1 + p[i] > n) return false;
    const uint8_t* tpdu = p + i + 1;
    const size_t tpdu_len = p[i];

    // RP-ACK MS to network, with an empty SMS-DELIVER-REPORT (24.011 7.3.3)
    const uint8_t ack[] = {0x02, mr, 0x41, 0x02, 0x00, 0x00};
    out.ack.assign(ack, ack + sizeof(ack));

    decode_deliver(tpdu, tpdu_len, out);
    if (out.id.empty()) out.id = hex(p, n);
    return true;
}

/////////////////////////////////////////////////////////////////////////////
// 3GPP2: C.S0015-B transport layer (3.4) and bearer data (4.5)

enum {
    kTeleserviceWmt = 4098,   // CMT-95
    kTeleserviceWemt = 4101,  // enhanced, with user data header
};

// 3.4.3.3 address
bool cdma_address(const uint8_t* p, size_t n, std::string& out) {
    Bits b(p, n);
    const bool digit_mode = b.get(1);
    const bool number_mode = b.get(1);
    unsigned type = 0;
    if (digit_mode) {
        type = b.get(3);
        if (!number_mode) b.get(4);  // numbering plan
    }
    const unsigned fields = b.get(8);

    out.clear();
    if (digit_mode && !number_mode && type == 1) out += '+';  // international
    for (unsigned i = 0; i < fields && b.ok(); ++i) {
        if (!digit_mode) {
            static const char dtmf[] = "?1234567890*#???";
            out += dtmf[b.get(4)];
        } else {
            out += static_cast<char>(b.get(8));
        }
    }
    return b.ok();
}

// 4.5.2 user data, after the bearer data's header indicator is known
bool cdma_user_data(const uint8_t* p, size_t n, bool header,
                    std::string& out) {
    Bits b(p, n);
    const unsigned encoding = b.get(5);
    if (encoding == 1) return false;  // IS-91 extended protocol
    const unsigned fields = b.get(8);
    if (!b.ok()) return false;

    // Realign the CHARi fields to a byte boundary
    std::vector<uint8_t> data;
    while (b.left() >= 8) data.push_back(b.get(8));
    if (b.left()) {
        const unsigned rest = b.left();
        data.push_back(b.get(rest) << (8 - rest));
    }

    const size_t udh = header ? (data.empty() ? 1 : data[0] + 1u) : 0;
    if (udh > data.size()) return false;

    switch (encoding) {
        case 2:    // 7-bit ASCII
        case 3: {  // IA5
            const size_t skip = (udh * 8 + 6) / 7;
            if (skip > fields) return false;
            Bits c(data.data(), data.size());
            c.skip(skip * 7);
            out.clear();
            for (size_t i = skip; i < fields; ++i) {
                const unsigned ch = c.get(7);
                if (ch == '\n' || ch == '\r' || (ch >= 0x20 && ch < 0x7f))
                    out += static_cast<char>(ch);
                else
                    out += '?';
            }
            return c.ok();
        }
        case 4: {  // UTF-16
            const size_t start = udh + udh % 2;
            const size_t skip = start / 2;
            if (skip > fields || start + (fields - skip) * 2 > data.size())
                return false;
            return utf16be_to_utf8(data.data() + start, (fields - skip) * 2,
                                   out);
        }
        case 8:  // Latin-1
            if (fields < udh || fields > data.size()) return false;
            out = latin1_to_utf8(data.data() + udh, fields - udh);
            return true;
        case 9: {  // GSM 7-bit default alphabet
            const size_t skip = (udh * 8 + 6) / 7;
            if (skip > fields) return false;
            std::vector<uint8_t> sept;
            if (!gsm7_unpack(data.data(), data.size(), skip * 7,
                             fields - skip, sept))
                return false;
            out = gsm7_to_utf8(sept);
            return true;
        }
        default:  // octet (binary), Shift-JIS, Korean, ...
            return false;
    }
}

int bcd(uint8_t b) { return (b >> 4) * 10 + (b & 0xf); }

bool decode_3gpp2(const uint8_t* p, size_t n, Message& out) {
    if (n < 1) return false;

    // SMS Acknowledge (3.4.2.3): the verdict on one of ours, in Cause Codes
    if (p[0] == 2) {
        out.kind = Message::Ack;
        out.id = hex(p, n);
        for (size_t i = 1; i + 2 <= n && i + 2 + p[i + 1] <= n;
             i += 2 + p[i + 1]) {
            if (p[i] != 0x07 || p[i + 1] < 1) continue;
            const uint8_t* v = p + i + 2;
            out.ref = v[0] >> 2;
            out.accepted = (v[0] & 3) == 0;
            if (!out.accepted && p[i + 1] >= 2) out.cause = v[1];
            return true;
        }
        return false;
    }
    if (p[0] != 0) return true;  // broadcast: nothing to show or ack

    unsigned teleservice = 0;
    const uint8_t* addr = NULL;
    size_t addr_len = 0;
    const uint8_t* bearer = NULL;
    size_t bearer_len = 0;
    bool reply = false;
    unsigned reply_seq = 0;

    for (size_t i = 1; i < n;) {
        if (i + 2 > n || i + 2 + p[i + 1] > n) return false;
        const uint8_t id = p[i], len = p[i + 1];
        const uint8_t* v = p + i + 2;

        switch (id) {
            case 0x00:  // teleservice identifier
                if (len >= 2) teleservice = (v[0] << 8) | v[1];
                break;
            case 0x02:  // originating address
                addr = v;
                addr_len = len;
                break;
            case 0x06:  // bearer reply option
                if (len >= 1) {
                    reply = true;
                    reply_seq = v[0] >> 2;
                }
                break;
            case 0x08:  // bearer data
                bearer = v;
                bearer_len = len;
                break;
        }
        i += 2 + len;
    }

    // 3.4.2.3 SMS Acknowledge: the sender's address back as destination,
    // and Cause Codes with error class 0 (no error)
    if (reply) {
        out.ack.push_back(0x02);
        if (addr) {
            out.ack.push_back(0x04);
            out.ack.push_back(static_cast<uint8_t>(addr_len));
            out.ack.insert(out.ack.end(), addr, addr + addr_len);
        }
        out.ack.push_back(0x07);
        out.ack.push_back(0x01);
        out.ack.push_back(static_cast<uint8_t>(reply_seq << 2));
    }

    if (addr) cdma_address(addr, addr_len, out.sender);

    bool header = false;
    const uint8_t* user = NULL;
    size_t user_len = 0;
    for (size_t i = 0; bearer && i < bearer_len;) {
        if (i + 2 > bearer_len || i + 2 + bearer[i + 1] > bearer_len) break;
        const uint8_t id = bearer[i], len = bearer[i + 1];
        const uint8_t* v = bearer + i + 2;

        if (id == 0x00 && len >= 3) {  // message identifier
            Bits b(v, len);
            b.get(4);  // message type
            const unsigned msg_id = b.get(16);
            header = b.get(1);
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%u", msg_id);
            out.id = out.sender + "/" + buf;
        } else if (id == 0x01) {  // user data
            user = v;
            user_len = len;
        } else if (id == 0x03 && len >= 6) {  // message center time stamp
            int ts[6];
            for (int k = 0; k < 6; ++k) ts[k] = bcd(v[k]);
            ts[0] += ts[0] < 96 ? 2000 : 1900;
            out.timestamp = timestamp(ts);
        }
        i += 2 + len;
    }

    if (out.id.empty()) out.id = hex(p, n);

    if (user &&
        (teleservice == kTeleserviceWmt || teleservice == kTeleserviceWemt))
        out.has_text = cdma_user_data(user, user_len, header, out.text);

    return true;
}

}  // namespace

Format format_from_subtype(const std::string& subtype) {
    if (subtype == "vnd.3gpp.sms") return Format::Gpp;
    if (subtype == "vnd.3gpp2.sms") return Format::Gpp2;
    return Format::Unknown;
}

const char* format_mime(Format f) {
    switch (f) {
        case Format::Gpp: return "application/vnd.3gpp.sms";
        case Format::Gpp2: return "application/vnd.3gpp2.sms";
        default: return "application/octet-stream";
    }
}

bool decode(Format f, const uint8_t* p, size_t n, Message& out) {
    out = Message();
    out.format = f;

    bool ok = false;
    if (f == Format::Gpp) ok = decode_3gpp(p, n, out);
    if (f == Format::Gpp2) ok = decode_3gpp2(p, n, out);
    if (!out.has_text) out.text.clear();
    return ok;
}

namespace {

const size_t kMaxSeptets = 160;  // single part, 3GPP GSM 7-bit / 3GPP2 ASCII
const size_t kMaxUnits = 70;     // single part, UCS-2 / UTF-16

bool too_long(size_t have, size_t max, std::string& why) {
    char buf[96];
    std::snprintf(buf, sizeof(buf),
                  "too long for one SMS (%zu of %zu), concatenated SMS "
                  "not supported yet",
                  have, max);
    why = buf;
    return false;
}

bool encode_3gpp(const std::string& to, const std::vector<uint32_t>& text,
                 unsigned ref, const std::string& smsc,
                 std::vector<uint8_t>& out, std::string& why) {
    bool intl, sc_intl;
    std::string digits, sc_digits;
    if (!split_number(to, intl, digits)) return why = "bad number", false;
    if (!split_number(smsc, sc_intl, sc_digits))
        return why = "no SMSC number (set sms.smsc or receive an SMS first)",
               false;

    // SMS-SUBMIT (TS 23.040 9.2.2.2), no validity period or status report
    std::vector<uint8_t> tpdu;
    tpdu.push_back(0x01);
    tpdu.push_back(ref & 0xff);
    tpdu.push_back(static_cast<uint8_t>(digits.size()));
    tpdu.push_back(intl ? 0x91 : 0x81);
    bcd_digits(digits, tpdu);
    tpdu.push_back(0x00);  // PID

    std::vector<uint8_t> septets, ud;
    if (gsm7_encode(text, septets)) {
        if (septets.size() > kMaxSeptets)
            return too_long(septets.size(), kMaxSeptets, why);
        gsm7_pack(septets, ud);
        tpdu.push_back(0x00);  // DCS: GSM 7-bit
        tpdu.push_back(static_cast<uint8_t>(septets.size()));
    } else {
        utf16be(text, ud);
        if (ud.size() / 2 > kMaxUnits)
            return too_long(ud.size() / 2, kMaxUnits, why);
        tpdu.push_back(0x08);  // DCS: UCS-2
        tpdu.push_back(static_cast<uint8_t>(ud.size()));
    }
    tpdu.insert(tpdu.end(), ud.begin(), ud.end());

    // RP-DATA MS to network (TS 24.011 7.3.1.2)
    std::vector<uint8_t> da;
    da.push_back(sc_intl ? 0x91 : 0x81);
    bcd_digits(sc_digits, da);

    out.clear();
    out.push_back(0x00);
    out.push_back(ref & 0xff);
    out.push_back(0x00);  // RP-OA: empty
    out.push_back(static_cast<uint8_t>(da.size()));
    out.insert(out.end(), da.begin(), da.end());
    out.push_back(static_cast<uint8_t>(tpdu.size()));
    out.insert(out.end(), tpdu.begin(), tpdu.end());
    return true;
}

// MSB-first bit packing for C.S0015 fields
class BitWriter {
   public:
    void put(uint32_t v, unsigned bits) {
        for (unsigned i = bits; i-- > 0; ++n_) {
            if (n_ % 8 == 0) b_.push_back(0);
            if ((v >> i) & 1) b_.back() |= 0x80 >> (n_ % 8);
        }
    }
    const std::vector<uint8_t>& bytes() const { return b_; }

   private:
    std::vector<uint8_t> b_;
    size_t n_ = 0;
};

void param(std::vector<uint8_t>& out, uint8_t id,
           const std::vector<uint8_t>& v) {
    out.push_back(id);
    out.push_back(static_cast<uint8_t>(v.size()));
    out.insert(out.end(), v.begin(), v.end());
}

bool encode_3gpp2(const std::string& to, const std::vector<uint32_t>& text,
                  unsigned ref, unsigned msg_id, std::vector<uint8_t>& out,
                  std::string& why) {
    bool intl;
    std::string digits;
    if (!split_number(to, intl, digits)) return why = "bad number", false;

    // Destination address (3.4.3.3): DTMF digits, or 8-bit digits with
    // number type international when there's a +
    BitWriter addr;
    if (!intl) {
        addr.put(0, 1);  // DIGIT_MODE: 4-bit DTMF
        addr.put(0, 1);  // NUMBER_MODE
        addr.put(static_cast<uint32_t>(digits.size()), 8);
        for (size_t i = 0; i < digits.size(); ++i) {
            const char c = digits[i];
            addr.put(c == '0' ? 10 : c == '*' ? 11 : c == '#' ? 12 : c - '0',
                     4);
        }
    } else {
        addr.put(1, 1);  // DIGIT_MODE: 8-bit
        addr.put(0, 1);  // NUMBER_MODE: not a data network address
        addr.put(1, 3);  // NUMBER_TYPE: international
        addr.put(1, 4);  // NUMBER_PLAN: ISDN/telephony
        addr.put(static_cast<uint32_t>(digits.size()), 8);
        for (size_t i = 0; i < digits.size(); ++i) addr.put(digits[i], 8);
    }

    // Message identifier (4.5.1): SUBMIT
    BitWriter id;
    id.put(2, 4);
    id.put(msg_id & 0xffff, 16);
    id.put(0, 1);  // no user data header
    id.put(0, 3);

    // User data (4.5.2): 7-bit ASCII if it fits, else UTF-16
    bool ascii = true;
    for (size_t i = 0; i < text.size(); ++i)
        if (!(text[i] == '\n' || text[i] == '\r' ||
              (text[i] >= 0x20 && text[i] < 0x7f)))
            ascii = false;

    BitWriter ud;
    if (ascii) {
        if (text.size() > kMaxSeptets)
            return too_long(text.size(), kMaxSeptets, why);
        ud.put(2, 5);
        ud.put(static_cast<uint32_t>(text.size()), 8);
        for (size_t i = 0; i < text.size(); ++i) ud.put(text[i], 7);
    } else {
        std::vector<uint8_t> u16;
        utf16be(text, u16);
        if (u16.size() / 2 > kMaxUnits)
            return too_long(u16.size() / 2, kMaxUnits, why);
        ud.put(4, 5);
        ud.put(static_cast<uint32_t>(u16.size() / 2), 8);
        for (size_t i = 0; i < u16.size(); ++i) ud.put(u16[i], 8);
    }

    std::vector<uint8_t> bearer;
    param(bearer, 0x00, id.bytes());
    param(bearer, 0x01, ud.bytes());

    const uint8_t teleservice[] = {kTeleserviceWmt >> 8,
                                   kTeleserviceWmt & 0xff};
    const uint8_t reply[] = {static_cast<uint8_t>((ref & 0x3f) << 2)};

    out.clear();
    out.push_back(0x00);  // point-to-point
    param(out, 0x00,
          std::vector<uint8_t>(teleservice, teleservice + sizeof(teleservice)));
    param(out, 0x04, addr.bytes());
    param(out, 0x06, std::vector<uint8_t>(reply, reply + 1));  // ack it
    param(out, 0x08, bearer);
    return true;
}

}  // namespace

bool encode_submit(Format f, const std::string& to, const std::string& text,
                   unsigned ref, unsigned msg_id, const std::string& smsc,
                   std::vector<uint8_t>& out, std::string& why) {
    std::vector<uint32_t> cps;
    if (!utf8_decode(text, cps)) return why = "text is not UTF-8", false;
    if (cps.empty()) return why = "empty message", false;

    if (f == Format::Gpp) return encode_3gpp(to, cps, ref, smsc, out, why);
    if (f == Format::Gpp2) return encode_3gpp2(to, cps, ref, msg_id, out, why);
    return why = "unknown SMS format", false;
}

bool submit_ref(Format f, const uint8_t* p, size_t n, unsigned& ref) {
    if (f == Format::Gpp) {
        if (n < 2 || (p[0] & 7) != 0) return false;  // RP-DATA MS to network
        ref = p[1];
        return true;
    }
    if (f == Format::Gpp2) {
        if (n < 1 || p[0] != 0) return false;
        for (size_t i = 1; i + 2 <= n && i + 2 + p[i + 1] <= n;
             i += 2 + p[i + 1]) {
            if (p[i] == 0x06 && p[i + 1] >= 1) {
                ref = p[i + 2] >> 2;
                return true;
            }
        }
    }
    return false;
}

bool unbase64(const std::string& in, std::vector<uint8_t>& out) {
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        int v;
        if (c >= 'A' && c <= 'Z') {
            v = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            v = c - 'a' + 26;
        } else if (c >= '0' && c <= '9') {
            v = c - '0' + 52;
        } else if (c == '+' || c == '-') {
            v = 62;
        } else if (c == '/' || c == '_') {
            v = 63;
        } else if (c == '=' || c == '\r' || c == '\n' || c == ' ') {
            continue;
        } else {
            return false;
        }
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((acc >> bits) & 0xff);
        }
    }
    return true;
}

std::string base64(const uint8_t* p, size_t n) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = p[i] << 16;
        if (i + 1 < n) v |= p[i + 1] << 8;
        if (i + 2 < n) v |= p[i + 2];
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
        out += i + 1 < n ? tbl[(v >> 6) & 63] : '=';
        out += i + 2 < n ? tbl[v & 63] : '=';
    }
    return out;
}

}  // namespace sms
}  // namespace nekoims
