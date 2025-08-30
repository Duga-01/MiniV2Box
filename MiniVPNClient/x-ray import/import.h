#ifndef MINIVPNCLIENT_IMPORT_H
#define MINIVPNCLIENT_IMPORT_H

#endif //MINIVPNCLIENT_IMPORT_H

#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <unordered_map>
#include <nlohmann/json.hpp>

namespace minivpn {

// VLESS parsed data (REALITY/uTLS fields included)
struct VlessEntry {
    std::string uuid;
    std::string host;
    uint16_t    port{443};
    std::string flow{"xtls-rprx-vision"};
    std::string security;        // "reality" | "tls" | "none"
    std::string encryption{"none"};
    std::string pbk;             // REALITY public_key
    std::string sid;             // REALITY short_id (0..8 hex)
    std::string sni;             // TLS SNI
    std::string fp{"chrome"};    // uTLS fingerprint
    std::vector<std::string> alpn; // ["h2","http/1.1"] etc
    std::string net{"tcp"};      // transport hint (tcp/ws/h2)
    std::string tag;             // from URI fragment
};

// Shadowsocks parsed data (SIP002 or base64 scheme)
struct SsEntry {
    std::string method;
    std::string password;
    std::string host;
    uint16_t    port{0};
    std::string plugin;          // raw plugin string if present
    std::string tag;             // from fragment
};

class Importer {
public:
    static std::vector<nlohmann::json> import_uris(const std::vector<std::string>& uris);

    static std::optional<VlessEntry> parse_vless_uri(const std::string& uri);
    static std::optional<SsEntry>    parse_ss_uri(const std::string& uri);

    static nlohmann::json build_vless_outbound(const VlessEntry& e, const std::string& tag="vless-imported");
    static nlohmann::json build_ss_outbound(const SsEntry& e, const std::string& tag="ss-imported");

private:
    static std::string url_decode(const std::string& s);
    static std::unordered_map<std::string,std::string> parse_query(const std::string& q);
    static bool b64_decode(const std::string& in, std::string& out);
    static bool decode_ss_userinfo(const std::string& s, std::string& method, std::string& password);
    static std::vector<std::string> split_csv(const std::string& s);
    static bool is_hex_short_id(const std::string& sid);
    static bool istarts_with(const std::string& s, const char* pfx);
};

} // namespace minivpn
