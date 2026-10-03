#include "simcard_client.h"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

namespace nekoims {

namespace {

const long kTimeoutMs = 5000;

size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    static_cast<std::string*>(userdata)->append(ptr, size * nmemb);
    return size * nmemb;
}

std::string to_hex(const std::vector<uint8_t>& v) {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (size_t i = 0; i < v.size(); ++i) {
        s += digits[v[i] >> 4];
        s += digits[v[i] & 0xf];
    }
    return s;
}

bool from_hex(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2) return false;
    out.clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned v = 0;
        for (size_t j = i; j < i + 2; ++j) {
            char c = s[j];
            v <<= 4;
            if (c >= '0' && c <= '9')
                v |= c - '0';
            else if (c >= 'a' && c <= 'f')
                v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                v |= c - 'A' + 10;
            else
                return false;
        }
        out.push_back(static_cast<uint8_t>(v));
    }
    return true;
}

}  // namespace

SimcardClient::SimcardClient(const std::string& endpoint) {
    const std::string unix_prefix = "unix:";
    if (endpoint.compare(0, unix_prefix.size(), unix_prefix) == 0) {
        unix_path_ = endpoint.substr(unix_prefix.size());
        base_url_ = "http://simcard/";
    } else {
        base_url_ = endpoint;
        if (base_url_.empty() || base_url_[base_url_.size() - 1] != '/')
            base_url_ += '/';
    }
}

bool SimcardClient::get(const std::string& query, std::string& body,
                        std::string& error) const {
    CURL* curl = curl_easy_init();
    if (!curl) {
        error = "curl_easy_init failed";
        return false;
    }

    const std::string url = base_url_ + "?" + query;
    char errbuf[CURL_ERROR_SIZE] = "";
    long code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    if (!unix_path_.empty())
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, unix_path_.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, kTimeoutMs);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        error = errbuf[0] ? errbuf : curl_easy_strerror(rc);
        return false;
    }

    if (code != 200) {
        error = "HTTP " + std::to_string(code);
        try {
            error += ": " +
                     nlohmann::json::parse(body).at("error").get<std::string>();
        } catch (const nlohmann::json::exception&) {
        }
        return false;
    }

    return true;
}

bool SimcardClient::imsi(std::string& out, std::string& error) const {
    std::string body;
    if (!get("type=imsi", body, error)) return false;

    try {
        out = nlohmann::json::parse(body).at("imsi").get<std::string>();
    } catch (const nlohmann::json::exception& e) {
        error = std::string("bad response: ") + e.what();
        return false;
    }

    return true;
}

AkaResult SimcardClient::authenticate(const std::vector<uint8_t>& rand,
                                      const std::vector<uint8_t>& autn,
                                      const std::string& app) const {
    AkaResult r;
    std::string body;

    // IMS AKA runs on the ISIM where there is one (TS 33.203 6.1), unless
    // the operator's keys only work on the USIM; servers that don't know
    // "app" use the USIM.
    if (!get("type=rand-autn&rand=" + to_hex(rand) + "&autn=" + to_hex(autn) +
                 "&app=" + app,
             body, r.error))
        return r;

    try {
        nlohmann::json j = nlohmann::json::parse(body);

        if (j.contains("auts") && j["auts"].is_string()) {
            if (!from_hex(j["auts"].get<std::string>(), r.auts)) {
                r.error = "bad AUTS hex";
                return r;
            }
            r.sync_failure = true;
            return r;
        }

        if (!j.at("res").is_string() ||
            !from_hex(j["res"].get<std::string>(), r.res) ||
            !from_hex(j.at("ck").get<std::string>(), r.ck) ||
            !from_hex(j.at("ik").get<std::string>(), r.ik)) {
            r.error = "bad RES/CK/IK in response";
            return r;
        }
    } catch (const nlohmann::json::exception& e) {
        r.error = std::string("bad response: ") + e.what();
        return r;
    }

    r.ok = true;
    return r;
}

}  // namespace nekoims
