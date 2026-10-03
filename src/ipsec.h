// IMS IPsec for sec-agree (TS 33.203 7, TS 24.229 5.1.1.2.1, RFC 3329).
//
// The P-CSCF picks one of our Security-Client offers in its 401; once the AKA
// gives CK/IK, four transport-mode ESP SAs and their policies go into the
// kernel. There is no IKE: keys come from the AKA, SPIs and ports from the
// headers. For now this shells out to `ip xfrm` in the current netns.
//
// The UE uses one port for both port-c and port-s, so libre keeps its single
// SIP socket; the P-CSCF's two ports keep the four SAs apart.
//
// Currently, 
// Behind an XFRM interface (the ePDG tunnel's ims0), the kernel checks
// inbound policy for packets that arrive on it with an SA in their secpath
// in the interface's link netns, by its if_id, where charon's tunnel policy
// would reject our transport SA. So the inbound policies are mirrored there
// (assumed to be PID 1's netns, as with strongswan-dialer.py).
// Though this makes the present implementation Linux-specific, 
// it is the only way to get sec-agree working with the IMS server. 
// A more generic implementation will be needed for other platforms.

#ifndef NEKOIMS_IPSEC_H
#define NEKOIMS_IPSEC_H

#include <cstdint>
#include <string>
#include <vector>

namespace nekoims {

// One ipsec-3gpp entry of a Security-Client/-Server/-Verify header.
struct SecMech {
    std::string alg;   // hmac-md5-96, hmac-sha-1-96
    std::string ealg;  // aes-cbc, null (absent means null)
    uint32_t spi_c = 0, spi_s = 0;
    uint16_t port_c = 0, port_s = 0;
    double q = 0;
};

// The ipsec-3gpp entries of a header value (comma-separated list).
std::vector<SecMech> parse_security(const std::string& value);

// Highest-q entry we can install, or false.
bool pick_security(const std::vector<SecMech>& offers, SecMech& out);

// Our Security-Client value for spi_c/spi_s on port (both port-c and port-s).
std::string security_client(uint32_t spi_c, uint32_t spi_s, uint16_t port);

// The SAs and policies of one registration.
class IpsecSet {
   public:
    IpsecSet() = default;
    ~IpsecSet() { remove(); }
    IpsecSet(const IpsecSet&) = delete;
    IpsecSet& operator=(const IpsecSet&) = delete;

    // local/remote: IP addresses (no port); covers SIP over UDP and TCP.
    bool install(const std::string& local, const std::string& remote,
                 uint16_t port, uint32_t spi_c,
                 uint32_t spi_s, const SecMech& server,
                 const std::vector<uint8_t>& ck,
                 const std::vector<uint8_t>& ik, std::string& why);
    void remove();
    // Forget policies other also has: it overwrote them (same selectors), so
    // remove() must leave them alone.
    void forget_shared(const IpsecSet& other);
    bool installed() const { return !policies_.empty() || !reqids_.empty(); }

    // Per-SA packet/byte/error counters and the kernel's non-zero XFRM
    // error counters, for the log when the network goes quiet.
    std::string stats() const;

    // Leftovers of a previous run (our reqid range) in this netns.
    static void flush_stale();

   private:
    std::vector<uint32_t> reqids_;
    std::vector<std::string> policies_;  // "ip xfrm policy delete" args
    std::vector<std::string> link_policies_;  // same, in the link netns
};

}  // namespace nekoims

#endif
