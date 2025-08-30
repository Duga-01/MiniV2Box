// src/mesh.cpp
#include "minivpn/mesh.hpp"

#include <chrono>
#include <thread>

using namespace minivpn;

static inline void u16be(uint8_t* p, uint16_t v){ p=uint8_t(v>>8); p[1]=uint8_t(v); }
static inline void u32be(uint8_t* p, uint32_t v){ p=uint8_t(v>>24); p[1]=uint8_t(v>>16); p[2]=uint8_t(v>>8); p[3]=uint8_t(v); }

MeshNode::MeshNode(std::string self_id, std::string signal_url, bool e2e_enabled, E2EClient& e2e)
: self_id_(std::move(self_id)), signal_url_(std::move(signal_url)), e2e_enabled_(e2e_enabled), e2e_(e2e) {} // [15]

void MeshNode::attachPeer(const std::string& peer_id, std::shared_ptr<IDataChannel> dc) {
    links_[peer_id] = Link{dc, -1, std::nullopt, "p2p"};
    dc->onMessage = [this, peer_id](const std::vector<uint8_t>& b){ this->on_frame(peer_id, b); };
    // HELLO
    json hdr = {{"src", self_id_}, {"dst", peer_id}, {"via", peer_id}, {"seq", (uint64_t) std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()}};
    send_raw(peer_id, FLAG_CTRL, HELLO, 8, hdr, {});
} // [15]

std::vector<uint8_t> MeshNode::pack(uint8_t flags, uint8_t typ, uint8_t ttl, const std::vector<uint8_t>& hdr, const std::vector<uint8_t>& body) {
    std::vector<uint8_t> out; out.reserve(12+hdr.size()+body.size());
    out.push_back('M'); out.push_back('V');
    out.push_back(VER);
    out.push_back(flags);
    out.push_back(ttl);
    out.push_back(typ);
    uint8_t meta[6];
    u16be(meta, (uint16_t)hdr.size());
    u32be(meta+2, (uint32_t)body.size());
    out.insert(out.end(), meta, meta+6);
    out.insert(out.end(), hdr.begin(), hdr.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
} // [15]

void MeshNode::send_raw(const std::string& peer_id, uint8_t flags, uint8_t typ, uint8_t ttl, const json& hdrj, const std::vector<uint8_t>& payload) {
    auto it = links_.find(peer_id);
    if (it == links_.end() || !it->second.dc || !it->second.dc->open()) return;

    auto dump = hdrj.dump();
    std::vector<uint8_t> hdr(dump.begin(), dump.end());
    auto frame = pack(flags, typ, ttl, hdr, payload);

    // Backpressure
    for (int i=0;i<200;i++){
        if (it->second.dc->bufferedAmount() < BUF_HIGH) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    it->second.dc->send(frame.data(), frame.size());
    for (int i=0;i<500;i++){
        if (it->second.dc->bufferedAmount() < BUF_LOW) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
} // [11]

void MeshNode::learn_route(const std::string& src, const std::string& via, std::optional<int> rtt) {
    if (src == self_id_) return;
    auto& r = routes_[src];
    r.next_hop = via;
    if (rtt) r.rtt = *rtt;
    r.last_seen = (double) std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
} // [16]

void MeshNode::on_frame(const std::string& from_peer, const std::vector<uint8_t>& data) {
    if (data.size()<12 || data!='M' || data[1]!='V' || data[2]!=VER) return;
    uint8_t flags = data[3], ttl = data[4], typ = data[5];
    uint16_t hdr_len = (data[6]<<8)|data[7];
    uint32_t ct_len = (uint32_t)data[8]<<24 | (uint32_t)data[9]<<16 | (uint32_t)data[17]<<8 | (uint32_t)data[18];
    if (hdr_len>MAX_HDR || ct_len>MAX_CT) return;
    if (12+hdr_len+ct_len>data.size()) return;

    std::vector<uint8_t> hdrb(data.begin()+12, data.begin()+12+hdr_len);
    std::vector<uint8_t> body (data.begin()+12+hdr_len, data.begin()+12+hdr_len+ct_len);

    json hdr;
    try { hdr = json::parse(std::string(hdrb.begin(), hdrb.end())); } catch (...) { return; }
    std::string src = hdr.value("src", ""); std::string dst = hdr.value("dst", "");
    if (src.empty() || dst.empty()) return;

    learn_route(src, from_peer);

    // CTRL
    if (flags & FLAG_CTRL) {
        if (typ == HELLO) return;
        if (typ == PING) {
            json obj; try { obj = json::parse(std::string(body.begin(), body.end())); } catch(...) { obj = json::object(); }
            json pong_hdr = {{"src", self_id_}, {"dst", src}, {"via", from_peer}, {"seq", obj.value("seq", 0)}};
            send_raw(from_peer, FLAG_CTRL, PONG, 6, pong_hdr, std::vector<uint8_t>{});
            return;
        }
        if (typ == PONG) {
            // здесь можно обновить EMA‑RTT (при наличии timestamp в obj)
            return;
        }
        if (typ == RREQ) {
            if (dst == self_id_) {
                json hdr2 = {{"src", self_id_}, {"dst", src}, {"via", from_peer}, {"seq", hdr.value("seq", 0)}};
                send_raw(from_peer, FLAG_CTRL, RREP, 6, hdr2, {});
            } else if (ttl>0) {
                for (auto& kv : links_) {
                    if (kv.first == from_peer) continue;
                    json nh = {{"src", src}, {"dst", dst}, {"via", kv.first}, {"seq", hdr.value("seq", 0)}};
                    send_raw(kv.first, FLAG_CTRL, RREQ, ttl-1, nh, {});
                }
            }
            return;
        }
        if (typ == RREP) {
            if (dst == self_id_) learn_route(src, from_peer);
            else if (ttl>0 && links_.count(from_peer)) {
                std::string nh = routes_.count(dst)? routes_[dst].next_hop : from_peer;
                json nhdr = {{"src", src}, {"dst", dst}, {"via", nh}, {"seq", hdr.value("seq", 0)}};
                send_raw(nh, FLAG_CTRL, RREP, ttl-1, nhdr, {});
            }
            return;
        }
        return;
    }

    // DATA
    if (typ == DATA) {
        if (dst == self_id_) {
            std::vector<uint8_t> plaintext = body;

            // E2E decrypt (DR header len + header + ct)
            if (flags & FLAG_E2E && e2e_enabled_) {
                if (plaintext.size()<2) return;
                uint16_t dr_len = (plaintext<<8)|plaintext[1];
                if (2+dr_len>plaintext.size()) return;
                Bytes dr_hdr(plaintext.begin()+2, plaintext.begin()+2+dr_len);
                Bytes ct    (plaintext.begin()+2+dr_len, plaintext.end());
                json adj = {{"src", src}, {"dst", dst}, {"seq", hdr.value("seq", 0)}};
                auto adjstr = adj.dump();
                Bytes ad(adjstr.begin(), adjstr.end());
                auto pt = e2e_.decrypt(src, DRMessage{dr_hdr, ct}, ad);
                if (!pt) return;
                plaintext.assign(pt->begin(), pt->end());
            }

            if (app_handler_) app_handler_(src, plaintext);
            return;
        } else {
            if (ttl==0) return;
            std::string nh = routes_.count(dst)? routes_[dst].next_hop : std::string();
            if (nh.empty()) return;
            json hdr2 = {{"src", src}, {"dst", dst}, {"via", nh}, {"seq", hdr.value("seq", 0)},
                         {"frag_id", hdr.value("frag_id", 0)}, {"frag_idx", hdr.value("frag_idx", 1)}, {"frag_total", hdr.value("frag_total", 1)}};
            send_raw(nh, flags, DATA, ttl-1, hdr2, body);
            return;
        }
    }
} // [15]

void MeshNode::reassembly_cleanup() {
    // при необходимости: хранить карту (src,frag_id) -> {received,total,ts} и чистить по таймауту
} // [15]

void MeshNode::prune_seen() {
    // реализовать LRU-память seq с TTL
} // [16]

