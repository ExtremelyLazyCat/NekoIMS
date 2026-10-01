#pragma once

#include <string>

namespace nekoims {

// Extra headers for every BYE we send, each ending in CRLF.
void set_bye_headers(const std::string& hdrs);

}  // namespace nekoims
