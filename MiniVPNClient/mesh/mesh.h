#ifndef MINIVPNCLIENT_MESH_H
#define MINIVPNCLIENT_MESH_H

#endif //MINIVPNCLIENT_MESH_H

#pragma once
#include "e2e.hpp"
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <functional>
#include <memory>

namespace minivpn {

using json = nlohmann::json;

struct MeshPath { std::string via; int latency_ms; std::optional<std::pair<std::string,int>> relay_addr; };

class IDataChannel {
public:
    virtual ~IDataChannel() = default;
    virtual void send(const uint8_t* data, size_t len) = 0;
    virtual size_t bufferedAmount() const = 0;
    virtual bool open() const = 0;
    virtual void close() = 0;
    std::function<void(const std::vector<uint8_t>&)> onMessage;
};

class MeshNode {
public:
    using PayloadHandler = std::function<void(const std::string&, const std::vector<uint8_t>&)>;

    MeshNode(std::string self_id, std::string signal_url, bool e2e_enabled, E2EClient& e2e);

    void attachPeer(const std::string& peer_id, std::shared_ptr<IDataChannel> dc);
    void send(const std::string& dst_id, const std::vector<uint8_t>& payload);
    void on_secure(PayloadHandler cb) { app_handler_ = std::move(cb); }

    void reassembly_cleanup();
    void prune_seen();

private:
    static constexpr uint8_t VER = 1;
    static constexpr uint8_t FLAG_E2E = 0x01;
    static constexpr uint8_t FLAG_CTRL = 0x02;
    enum Type : uint8_t { HELLO=0x01, RREQ=0x02, RREP=0x03, PING=0x04, PONG=0x05, DATA=0x10 };

    static constexpr size_t FRAG_MAX = 32*1024;
    static constexpr size_t MAX_HDR = 8*1024;
    static constexpr size_t MAX_CT  = 4*1024*1024;
    static constexpr size_t BUF_HIGH= 512*1024;
    static constexpr size_t BUF_LOW = 128*1024;

    struct Link { std::shared_ptr<IDataChannel> dc; int rtt_ms{-1}; std::optional<double> rtt_ema; std::string via{"unknown"}; };
    struct Route { std::string next_hop; int rtt{-1}; double last_seen{0}; double success{1.0}; };

    std::string self_id_, signal_url_;
    bool e2e_enabled_;
    E2EClient& e2e_;
    std::unordered_map<std::string, Link> links_;
    std::unordered_map<std::string, Route> routes_;
    std::unordered_map<uint64_t,double> seen_seq_;
    std::function<void(const std::string&, const std::vector<uint8_t>&)> app_handler_;

    static std::vector<uint8_t> pack(uint8_t flags, uint8_t typ, uint8_t ttl, const std::vector<uint8_t>& hdr, const std::vector<uint8_t>& body);
    void send_raw(const std::string& peer_id, uint8_t flags, uint8_t typ, uint8_t ttl, const json& hdr, const std::vector<uint8_t>& payload);
    void on_frame(const std::string& from_peer, const std::vector<uint8_t>& data);
    void learn_route(const std::string& src, const std::string& via, std::optional<int> rtt = std::nullopt);
};

} // namespace minivpn
