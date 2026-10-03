#include "netns.h"

#include <cerrno>
#include <cstdlib>

#include <re.h>
#include <baresip.h>

#ifdef __linux__
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#endif

namespace nekoims {

#ifdef __linux__

Netns::~Netns() {
    if (target_ >= 0) close(target_);
    if (home_ >= 0) close(home_);
}

int Netns::open(const std::string& path) {
    const std::string file =
        path.find('/') == std::string::npos ? "/run/netns/" + path : path;

    home_ = ::open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
    if (home_ < 0) return errno;

    target_ = ::open(file.c_str(), O_RDONLY | O_CLOEXEC);
    if (target_ < 0) {
        const int err = errno;
        warning("netns: cannot open %s: %m\n", file.c_str(), err);
        return err;
    }

    // Fail now rather than on the first call
    if (!set(true)) return EPERM;
    set(false);
    return 0;
}

bool Netns::set(bool target) {
    if (setns(target ? target_ : home_, CLONE_NEWNET) == 0) {
        in_target_ = target;
        return true;
    }

    // Stuck in the target would put the IMS side in the wrong namespace
    if (!target) {
        warning("netns: cannot return to the home namespace: %m\n", errno);
        abort();
    }
    warning("netns: cannot enter namespace: %m\n", errno);
    return false;
}

#else

Netns::~Netns() {}

int Netns::open(const std::string& path) {
    (void)path;
    warning("netns: network namespaces are Linux only\n");
    return ENOSYS;
}

bool Netns::set(bool target) { return !target; }

#endif

}  // namespace nekoims
