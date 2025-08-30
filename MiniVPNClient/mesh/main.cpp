// src/main.cpp
#include "minivpn/mesh.hpp"
#include "minivpn/e2e.hpp"
#include "minivpn/storage.hpp"

#include <sodium.h>
#include <iostream>
#include <memory>
#include <unordered_map>

// Loopback-канал для локального теста (без WebRTC)
class LoopDC : public minivpn::IDataChannel, public std::enable_shared_from_this<LoopDC> {
public:
    void connectPeer(std::shared_ptr<LoopDC> other){ peer_=other; }
    void send(const uint8_t* data, size_t len) override {
        if (auto p=peer_.lock()) {
            std::vector<uint8_t> v(data, data+len);
            if (p->onMessage) p->onMessage(v);
        }
    }
    size_t bufferedAmount() const override { return 0; }
    bool open() const override { return true; }
    void close() override {}
private:
    std::weak_ptr<LoopDC> peer_;
};

int main() {
    if (sodium_init()<0) return 1;

    // Простое in-memory хранилище
    struct MemStore : minivpn::IE2EStore {
        minivpn::Bytes ikp, ikb;
        std::unordered_map<std::string,minivpn::Bytes> sess;
        bool load(const std::string&) override { return true; }
        bool save(const std::string&) const override { return true; }
        void set_identity(const minivpn::Bytes& a,const minivpn::Bytes& b) override { ikp=a; ikb=b;}
        bool get_identity(minivpn::Bytes& a,minivpn::Bytes& b) const override { if (ikp.empty()) return false; a=ikp;b=ikb; return true;}
        bool acquire_opk(minivpn::Bytes&, minivpn::Bytes&) override { return false; }
        void put_session(const std::string& peer, const minivpn::Bytes& blob) override { sess[peer]=blob; }
        bool get_session(const std::string& peer, minivpn::Bytes& blob_out) const override { auto it=sess.find(peer); if(it==sess.end()) return false; blob_out=it->second; return true; }
    } sa, sb;

    // IK пары
    minivpn::Bytes a_priv(crypto_box_SECRETKEYBYTES), a_pub(crypto_box_PUBLICKEYBYTES);
    crypto_box_keypair(a_pub.data(), a_priv.data());
    minivpn::Bytes b_priv(crypto_box_SECRETKEYBYTES), b_pub(crypto_box_PUBLICKEYBYTES);
    crypto_box_keypair(b_pub.data(), b_priv.data());
    sa.set_identity(a_priv, a_pub);
    sb.set_identity(b_priv, b_pub);

    minivpn::E2EClient ea("A", sa), eb("B", sb);
    minivpn::X3DHPublicBundle bb{.ik_pub=b_pub, .spk_pub=b_pub, .spk_sig={}, .opk_pub=std::nullopt};
    minivpn::X3DHPublicBundle ab{.ik_pub=a_pub, .spk_pub=a_pub, .spk_sig={}, .opk_pub=std::nullopt};
    ea.initiate_session("B", bb);
    eb.initiate_session("A", ab);

    minivpn::MeshNode na("A", "http://signal", true, ea);
    minivpn::MeshNode nb("B", "http://signal", true, eb);

    auto ca = std::make_shared<LoopDC>();
    auto cb = std::make_shared<LoopDC>();
    ca->connectPeer(cb); cb->connectPeer(ca);

    na.attachPeer("B", ca);
    nb.attachPeer("A", cb);

    nb.on_secure([](const std::string& src, const std::vector<uint8_t>& msg){
        std::cout << "B got from " << src << ": " << std::string(msg.begin(), msg.end()) << "\n";
    });

    std::string text = "Hello E2E Mesh";
    na.send("B", std::vector<uint8_t>(text.begin(), text.end()));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return 0;
}
