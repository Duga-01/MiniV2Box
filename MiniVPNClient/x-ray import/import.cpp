#include "import.hpp"
#include <algorithm>
#include <sstream>
#include <cctype>
#include <cstring>
#include <stdexcept>

using json = nlohmann::json;
namespace minivpn {

bool Importer::istarts_with(const std::string& s, const char* pfx){
    size_t n = std::strlen(pfx);
    if (s.size()<n) return false;
    for (size_t i=0;i<n;i++) if (std::tolower((unsigned char)s[i]) != std::tolower((unsigned char)pfx[i])) return false;
    return true;
}

std::string Importer::url_decode(const std::string& s){
    std::string out; out.reserve(s.size());
    for (size_t i=0;i<s.size();++i){
        if (s[i]=='%' && i+2<s.size() && std::isxdigit((unsigned char)s[i+1]) && std::isxdigit((unsigned char)s[i+2])) {
            int v = std::stoi(s.substr(i+1,2), nullptr, 16);
            out.push_back(char(v));
            i+=2;
        } else if (s[i]=='+') out.push_back(' ');
        else out.push_back(s[i]);
    }
    return out;
}

std::unordered_map<std::string,std::string> Importer::parse_query(const std::string& qraw){
    std::unordered_map<std::string,std::string> q;
    std::string qstr = qraw;
    if (!qstr.empty() && qstr=='?') qstr.erase(0,1);
    std::istringstream is(qstr);
    std::string kv;
    while (std::getline(is, kv, '&')) {
        if (kv.empty()) continue;
        auto pos = kv.find('=');
        if (pos==std::string::npos) {
            q[url_decode(kv)] = "";
        } else {
            q[url_decode(kv.substr(0,pos))] = url_decode(kv.substr(pos+1));
        }
    }
    return q;
}

bool Importer::b64_decode(const std::string& in, std::string& out){
    static int T; static bool init=false;
    if (!init){ std::fill(T,T+256,-1); const char* tbl="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; for(int i=0;i<64;i++) T[(unsigned char)tbl[i]]=i; init=true; }
    std::string tmp; tmp.reserve(in.size()*3/4);
    int val=0, valb=-8;
    for (unsigned char c: in){
        if (std::isspace(c)) continue;
        if (c=='=') break;
        int d = T[c];
        if (d==-1) return false;
        val = (val<<6) + d; valb+=6;
        if (valb>=0){ tmp.push_back(char((val>>valb)&0xFF)); valb-=8; }
    }
    out.swap(tmp);
    return true;
}

bool Importer::decode_ss_userinfo(const std::string& s, std::string& method, std::string& password){
    auto pos = s.find(':');
    if (pos==std::string::npos) return false;
    method = s.substr(0,pos);
    password = s.substr(pos+1);
    return true;
}

std::vector<std::string> Importer::split_csv(const std::string& s){
    std::vector<std::string> v; std::string cur; std::istringstream is(s);
    while (std::getline(is, cur, ',')) if(!cur.empty()) v.push_back(cur);
    return v;
}

bool Importer::is_hex_short_id(const std::string& sid){
    if (sid.empty() || sid.size()>8) return false;
    return std::all_of(sid.begin(), sid.end(), [](unsigned char c){ return std::isxdigit(c); });
}

std::optional<VlessEntry> Importer::parse_vless_uri(const std::string& uri){
    if (!istarts_with(uri, "vless://")) return std::nullopt;
    std::string rest = uri.substr(8);
    // fragment -> tag
    std::string frag;
    auto hash = rest.find('#');
    if (hash!=std::string::npos){ frag = url_decode(rest.substr(hash+1)); rest = rest.substr(0, hash); }
    // query
    std::string query;
    auto qpos = rest.find('?');
    if (qpos!=std::string::npos){ query = rest.substr(qpos); rest = rest.substr(0,qpos); }
    // userinfo@host:port
    auto at = rest.find('@');
    if (at==std::string::npos) return std::nullopt;
    std::string uuid = rest.substr(0, at);
    std::string hostport = rest.substr(at+1);
    auto colon = hostport.rfind(':');
    if (colon==std::string::npos) return std::nullopt;
    std::string host = hostport.substr(0, colon);
    uint16_t port = uint16_t(std::stoi(hostport.substr(colon+1)));

    auto q = parse_query(query);
    VlessEntry e;
    e.uuid = uuid;
    e.host = host;
    e.port = port;
    if (q.count("flow"))       e.flow = q["flow"];
    if (q.count("security"))   e.security = q["security"];       // reality/tls/none
    if (q.count("encryption")) e.encryption = q["encryption"];   // usually "none"
    if (q.count("pbk"))        e.pbk = q["pbk"];
    if (q.count("sid"))        e.sid = q["sid"];
    if (q.count("sni"))        e.sni = q["sni"];
    if (q.count("fp"))         e.fp  = q["fp"];
    if (q.count("alpn"))       e.alpn = split_csv(q["alpn"]);
    if (q.count("type"))       e.net  = q["type"];               // net/type hint
    e.tag = frag;

    // sanity (не валидируем строго)
    if (!e.sid.empty() && !is_hex_short_id(e.sid)) {
        // допустим некорректный sid, просто примем как есть — клиент опенсорс
    }
    return e;
} // [11][12]

std::optional<SsEntry> Importer::parse_ss_uri(const std::string& uri){
    if (!istarts_with(uri, "ss://")) return std::nullopt;
    std::string rest = uri.substr(5);
    SsEntry out;

    // fragment
    auto hash = rest.find('#');
    if (hash!=std::string::npos){ out.tag = url_decode(rest.substr(hash+1)); rest = rest.substr(0, hash); }

    // query
    auto qpos = rest.find('?');
    std::string beforeQ = (qpos==std::string::npos)? rest : rest.substr(0,qpos);

    if (beforeQ.find('@') != std::string::npos) {
        // form: ss://method:password@host:port?plugin=...  (SIP002)
        std::string creds, hostport;
        auto at = beforeQ.find('@');
        creds = beforeQ.substr(0, at);
        hostport = beforeQ.substr(at+1);
        auto colon = hostport.rfind(':');
        if (colon==std::string::npos) return std::nullopt;
        out.host = hostport.substr(0, colon);
        out.port = uint16_t(std::stoi(hostport.substr(colon+1)));

        creds = url_decode(creds);
        if (!decode_ss_userinfo(creds, out.method, out.password)) return std::nullopt;

        if (qpos!=std::string::npos){
            auto q = parse_query(rest.substr(qpos));
            if (q.count("plugin")) out.plugin = q["plugin"];
        }
        return out;
    } else {
        // base64: ss://BASE64(method:password@host:port)
        std::string b64 = beforeQ;
        std::string plain;
        if (!b64_decode(b64, plain)) return std::nullopt;
        auto at = plain.find('@');
        if (at==std::string::npos) return std::nullopt;
        std::string creds = plain.substr(0, at);
        std::string hostport = plain.substr(at+1);
        auto colon = hostport.rfind(':');
        if (colon==std::string::npos) return std::nullopt;
        out.host = hostport.substr(0, colon);
        out.port = uint16_t(std::stoi(hostport.substr(colon+1)));
        if (!decode_ss_userinfo(creds, out.method, out.password)) return std::nullopt;

        if (qpos!=std::string::npos){
            auto q = parse_query(rest.substr(qpos));
            if (q.count("plugin")) out.plugin = q["plugin"];
        }
        return out;
    }
} // [10][6]

json Importer::build_vless_outbound(const VlessEntry& e, const std::string& tag){
    json tls = {
        {"enabled", true},
        {"server_name", e.sni.empty()? e.host : e.sni}
    };
    if (!e.alpn.empty()) tls["alpn"] = e.alpn;
    else tls["alpn"] = json::array({"h2","http/1.1"});

    tls["utls"] = { {"enabled", true}, {"fingerprint", e.fp.empty()? "chrome" : e.fp} };

    if (e.security=="reality" || !e.pbk.empty() || !e.sid.empty()) {
        tls["reality"] = { {"enabled", true} };
        if (!e.pbk.empty()) tls["reality"]["public_key"] = e.pbk;
        if (!e.sid.empty()) tls["reality"]["short_id"]   = e.sid;
    }

    json tr = { {"type", e.net.empty()? "tcp" : e.net} };

    json jb = {
        {"type", "vless"},
        {"tag",  tag},
        {"server", e.host},
        {"server_port", e.port},
        {"uuid", e.uuid},
        {"flow", e.flow.empty()? "xtls-rprx-vision" : e.flow},
        {"packet_encoding", "xudp"},
        {"transport", tr},
        {"tls", tls}
    };
    if (!e.encryption.empty()) jb["encryption"] = e.encryption;

    return jb;
} // [11][12]

json Importer::build_ss_outbound(const SsEntry& e, const std::string& tag){
    json jb = {
        {"type","shadowsocks"},
        {"tag", tag},
        {"server", e.host},
        {"server_port", e.port},
        {"method", e.method},
        {"password", e.password}
    };
    if (!e.plugin.empty()) jb["plugin"] = e.plugin;
    return jb;
} // [6]

std::vector<json> Importer::import_uris(const std::vector<std::string>& uris){
    std::vector<json> out;
    for (auto& u : uris){
        if (istarts_with(u, "vless://")) {
            auto e = parse_vless_uri(u);
            if (!e) continue;
            out.push_back(build_vless_outbound(*e, e->tag.empty()? "vless-imported" : e->tag));
        } else if (istarts_with(u, "ss://")) {
            auto e = parse_ss_uri(u);
            if (!e) continue;
            out.push_back(build_ss_outbound(*e, e->tag.empty()? "ss-imported" : e->tag));
        } else {
            // можно добавить vmess://, trojan:// и т.д. в будущем
        }
    }
    return out;
}

} // namespace minivpn
