// src/storage_files.cpp
#include "minivpn/storage.hpp"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>

using json = nlohmann::json;

namespace minivpn {
namespace {

static std::string b64enc(const Bytes& b){
    // Упростим: стандартная простая база; для продакшена предпочтительна libsodium base64
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; size_t i=0;
    for (; i+2<b.size(); i+=3) {
        uint32_t n = (uint32_t(b[i])<<16) | (uint32_t(b[i+1])<<8) | uint32_t(b[i+2]);
        out.push_back(tbl[(n>>18)&63]);
        out.push_back(tbl[(n>>12)&63]);
        out.push_back(tbl[(n>>6)&63]);
        out.push_back(tbl[n&63]);
    }
    if (i<b.size()) {
        uint32_t n = uint32_t(b[i])<<16;
        out.push_back(tbl[(n>>18)&63]);
        if (i+1<b.size()) {
            n |= (uint32_t(b[i+1])<<8);
            out.push_back(tbl[(n>>12)&63]);
            out.push_back(tbl[(n>>6)&63]);
            out.push_back('=');
        } else {
            out.push_back(tbl[(n>>12)&63]);
            out.push_back('=');
            out.push_back('=');
        }
    }
    return out;
}

static Bytes b64dec(const std::string& s){
    std::vector<int> T(256, -1); const char* tbl="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i=0;i<64;i++) T[(unsigned char)tbl[i]]=i;
    Bytes out; int val=0, valb=-8;
    for (unsigned char c: s) {
        if (T[c]==-1) { if (c=='=') break; else continue; }
        val=(val<<6)+T[c]; valb+=6;
        if (valb>=0) { out.push_back(uint8_t((val>>valb)&0xFF)); valb-=8; }
    }
    return out;
}

struct FileStore : IE2EStore {
    std::string path;
    Bytes ik_priv_, ik_pub_;
    struct OPK { Bytes priv, pub; };
    std::vector<OPK> opks;
    std::unordered_map<std::string, Bytes> sessions;

    bool load(const std::string& p) override {
        path = p;
        std::ifstream f(path);
        if (!f.good()) return true;
        json j = json::parse(f);
        ik_priv_ = b64dec(j["identity"]["priv"].get<std::string>());
        ik_pub_  = b64dec(j["identity"]["pub" ].get<std::string>());
        if (j.contains("opk")) {
            for (auto& o : j["opk"]) {
                OPK k; k.priv=b64dec(o["priv"].get<std::string>()); k.pub=b64dec(o["pub"].get<std::string>()); opks.push_back(std::move(k));
            }
        }
        if (j.contains("sessions")) {
            for (auto& [k,v] : j["sessions"].items()) {
                sessions[k] = b64dec(v.get<std::string>());
            }
        }
        return true;
    }

    bool save(const std::string& p) const override {
        std::filesystem::create_directories(std::filesystem::path(p).parent_path());
        auto tmp = p + ".tmp";
        json j;
        j["identity"] = {{"priv", b64enc(ik_priv_)}, {"pub", b64enc(ik_pub_)}};
        j["opk"] = json::array();
        for (auto& k : opks) j["opk"].push_back({{"priv", b64enc(k.priv)}, {"pub", b64enc(k.pub)}});
        json sess = json::object();
        for (auto& kv : sessions) sess[kv.first] = b64enc(kv.second);
        j["sessions"] = sess;
        {
            std::ofstream of(tmp, std::ios::binary|std::ios::trunc);
            of << j.dump(2);
        }
        std::filesystem::rename(tmp, p);
        return true;
    }

    void set_identity(const Bytes& ik_priv, const Bytes& ik_pub) override { ik_priv_=ik_priv; ik_pub_=ik_pub; }
    bool get_identity(Bytes& ik_priv, Bytes& ik_pub) const override { if (ik_priv_.empty()) return false; ik_priv=ik_priv_; ik_pub=ik_pub_; return true; }
    bool acquire_opk(Bytes& opk_priv, Bytes& opk_pub) override {
        if (opks.empty()) return false;
        auto k = std::move(opks.back()); opks.pop_back();
        opk_priv = std::move(k.priv); opk_pub = std::move(k.pub); return true;
    }
    void put_session(const std::string& peer, const Bytes& blob) override { sessions[peer]=blob; }
    bool get_session(const std::string& peer, Bytes& blob_out) const override {
        auto it = sessions.find(peer); if (it==sessions.end()) return false; blob_out = it->second; return true;
    }
};

} // namespace

std::unique_ptr<IE2EStore> make_file_store(const std::string& path) {
    auto fs = std::make_unique<FileStore>();
    fs->load(path);
    return fs;
}

} // namespace minivpn
