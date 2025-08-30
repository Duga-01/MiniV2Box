
#ifndef MINIVPNCLIENT_SINGBOX_RUNNER_H
#define MINIVPNCLIENT_SINGBOX_RUNNER_H

#endif //MINIVPNCLIENT_SINGBOX_RUNNER_H

// singbox_runner.hpp
#pragma once
#include "process_runner.h"
#include <nlohmann/json.h>
#include <filesystem>
#include <fstream>

struct Reality {
    std::string server, sni, public_key, short_id, user_id, flow;
    int port = 443;
    std::vector<std::string> alpn{"h2","http/1.1"};
};

struct Shadowsocks {
    std::string server, method, password;
    int port = 0;
};

struct Profile {
    std::string name = "Default";
    std::string protocol = "vless-reality"; // or "shadowsocks"
    std::optional<Reality> vless;
    std::optional<Shadowsocks> ss;
    std::vector<std::string> split_apps{};
    bool use_mesh = true;
    std::string cname_endpoint{};
    std::vector<std::string> tls_alpn{"h2","http/1.1"};
    std::string tls_server_name{};
    bool active = true;
};

class SingBoxRunner {
public:
    SingBoxRunner(std::string exe, std::filesystem::path runDir)
        : exe_(std::move(exe)), runDir_(std::move(runDir)) {
        std::filesystem::create_directories(runDir_);
        cfgPath_ = runDir_ / "singbox.json";
        logPath_ = runDir_ / "singbox.log";
    }

    bool startWithProfile(const Profile& p,
                          int meshPort1, int meshPort2,
                          std::function<void(const std::string&)> logSink) {
        auto cfg = renderConfig(p, meshPort1, meshPort2);
        if (!atomicWrite(cfgPath_, cfg)) return false;

        // опциональная валидация: sing-box check
        // можно запустить отдельным процессом и смотреть код выхода

        std::vector<std::string> args = {"run", "-c", cfgPath_.string()};
        auto onOut = [logSink](const std::string& s){ if (logSink) logSink(s); };
        auto onErr = [logSink](const std::string& s){ if (logSink) logSink(s); };
        auto onExit= [](int){};
        return runner_.start(args, runDir_.string(), onOut, onErr, onExit);
    }

    bool reloadProfile(const Profile& p, int meshPort1, int meshPort2,
                       std::function<void(const std::string&)> logSink) {
        stop();
        return startWithProfile(p, meshPort1, meshPort2, std::move(logSink));
    }

    void stop() { runner_.stop(); }
    bool running() const { return runner_.running(); }

private:
    nlohmann::json renderConfig(const Profile& p, int m1, int m2) {
        using json = nlohmann::json;

        std::vector<json> outbounds;
        std::vector<std::string> chain;

        if (p.protocol == "vless-reality" && p.vless) {
            const auto& r = *p.vless;
            std::string host = r.server;
            if (!p.cname_endpoint.empty()) host = p.cname_endpoint;
            json vless = {
                {"type","vless"},
                {"tag","vless-primary"},
                {"server",host},
                {"server_port",r.port},
                {"uuid",r.user_id},
                {"flow",r.flow},
                {"packet_encoding","xudp"},
                {"transport", {{"type","tcp"}}},
                {"tls", {
                    {"enabled", true},
                    {"server_name", p.tls_server_name.empty()? (r.sni.empty()? host : r.sni) : p.tls_server_name},
                    {"alpn", p.tls_alpn.empty()? r.alpn : p.tls_alpn},
                    {"utls", {{"enabled",true},{"fingerprint","chrome"}}},
                    {"reality", {{"enabled",true},{"public_key",r.public_key},{"short_id",r.short_id}}}
                }}
            };
            outbounds.push_back(vless);
            chain.push_back("vless-primary");
        }

        if (p.ss && !p.ss->server.empty()) {
            const auto& s = *p.ss;
            outbounds.push_back(json{
                {"type","shadowsocks"},{"tag","ss-fallback"},
                {"server",s.server},{"server_port",s.port},
                {"method",s.method},{"password",s.password}
            });
            chain.push_back("ss-fallback");
        }

        if (p.use_mesh) {
            outbounds.push_back(json{{"type","socks"},{"tag","mesh-hop-1"},{"server","127.0.0.1"},{"server_port",m1}});
            outbounds.push_back(json{{"type","socks"},{"tag","mesh-hop-2"},{"server","127.0.0.1"},{"server_port",m2}});
            chain.push_back("mesh-hop-1");
            chain.push_back("mesh-hop-2");
        }

        if (chain.empty()) chain.push_back("direct");
        outbounds.push_back(json{
            {"type","selector"},{"tag","auto-chain"},
            {"default", chain},{"outbounds", chain},
            {"interrupt_exist_connections", false}
        });

        json cfg = {
            {"log", {{"level","info"}}},
            {"dns", {{"servers", json::array({"https://1.1.1.1/dns-query"})}}},
            {"inbounds", json::array({
                json{
                    {"type","tun"},{"tag","tun-in"},
                    {"interface_name","minivpn0"},
                    {"address", json::array({"10.10.0.2/24"})},
                    {"mtu",1500},
                    {"auto_route",true},
                    {"strict_route",true}
                },
                json{{"type","socks"},{"tag","socks-in"},{"listen","127.0.0.1"},{"listen_port",10808},{"sniff",false}},
                json{{"type","http"},{"tag","http-in"},{"listen","127.0.0.1"},{"listen_port",10809}}
            })},
            {"outbounds", outbounds},
            {"route", {
                {"auto_detect_interface", true},
                {"rules", buildRules(p.split_apps)}
            }}
        };
        return cfg;
    }

    static nlohmann::json buildRules(const std::vector<std::string>& apps) {
        using json = nlohmann::json;
        std::vector<json> rules{
            json{{"protocol","dns"},{"outbound","direct"}},
            json{{"ip_cidr", json::array({"10.0.0.0/8","192.168.0.0/16"})},{"outbound","direct"}}
        };
        if (!apps.empty()) {
            rules.insert(rules.begin(), json{{"process_name", apps},{"outbound","auto-chain"}});
        }
        return rules;
    }

    static bool atomicWrite(const std::filesystem::path& path, const nlohmann::json& j) {
        std::filesystem::create_directories(path.parent_path());
        auto tmp = path;
        tmp += ".tmp";
        try {
            std::ofstream ofs(tmp, std::ios::binary|std::ios::trunc);
            ofs << j.dump(2);
            ofs.close();
            std::filesystem::rename(tmp, path);
            return true;
        } catch (...) { return false; }
    }

    std::string exe_;
    std::filesystem::path runDir_, cfgPath_, logPath_;
    ProcessRunner runner_{exe_};
};
