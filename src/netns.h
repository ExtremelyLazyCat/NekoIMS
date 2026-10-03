// Network namespace switching for the calling thread (Linux setns()).
//
// A socket stays in the namespace it was created in, so code that creates
// sockets can step into another namespace, create them, and step back. Used
// for the B2BUA's external side (b2bua.netns) when NekoIMS itself runs in
// the IMS namespace. Needs CAP_SYS_ADMIN over both namespaces (root, or the
// owner of an unprivileged user namespace).

#ifndef NEKOIMS_NETNS_H
#define NEKOIMS_NETNS_H

#include <string>

namespace nekoims {

class Netns {
   public:
    Netns() = default;
    ~Netns();
    Netns(const Netns&) = delete;
    Netns& operator=(const Netns&) = delete;

    // path: a namespace file (/proc/1/ns/net) or a name in /run/netns.
    // Remembers the calling thread's current namespace as home.
    int open(const std::string& path);

    // Switch to the target namespace (true) or home (false)
    bool set(bool target);
    bool in_target() const { return in_target_; }

   private:
    int home_ = -1;
    int target_ = -1;
    bool in_target_ = false;
};

// In the target namespace (or home) for the scope's lifetime, then back to
// wherever it was, so scopes nest: setting up one B2BUA leg can set up the
// other from inside its window. A null Netns does nothing.
class NetnsScope {
   public:
    NetnsScope(Netns* ns, bool target)
        : ns_(ns), prev_(ns && ns->in_target()) {
        switched_ = ns && prev_ != target && ns->set(target);
    }
    ~NetnsScope() {
        if (switched_) ns_->set(prev_);
    }
    NetnsScope(const NetnsScope&) = delete;
    NetnsScope& operator=(const NetnsScope&) = delete;

   private:
    Netns* ns_;
    bool prev_;
    bool switched_;
};

}  // namespace nekoims

#endif
