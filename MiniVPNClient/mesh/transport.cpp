// transport.cpp
#include "minivpn/transport.hpp"

#include <rtc/rtc.hpp>
#include <nlohmann/json.hpp>
#include <cstring>

using json = nlohmann::json;

namespace minivpn {

    DCAdapter::DCAdapter(std::shared_ptr<rtc::DataChannel> dc) : dc_(std::move(dc)) {
        dc_->onMessage([this](rtc::binary b){
            std::vector<uint8_t> v(b.size());
            std::memcpy(v.data(), b.data(), b.size());
            if (onMessage) onMessage(v);
        });
    } // [12]

    void DCAdapter::send(const uint8_t* data, size_t len) { dc_->send(reinterpret_cast<const std::byte*>(data), len); } // [12]
    size_t DCAdapter::bufferedAmount() const { return dc_->bufferedAmount(); } // [12]
    bool DCAdapter::open() const { return dc_->isOpen(); } // [12]
    void DCAdapter::close() { dc_->close(); } // [12]

    SignalClient::SignalClient(std::string base) : base_(std::move(base)) {} // [13]

    bool SignalClient::post_offer(const std::string& peer_id, const std::string& sdp, const std::string& type, std::string& out_answer_json) {
        // TODO: Реализуйте HTTP POST base_/offer с JSON телом {"peer":peer_id,"sdp":sdp,"type":type}
        // Рекомендуется Boost.Beast HTTP/HTTPS клиент (см. примеры Boost Beast JSON client)
        (void)peer_id; (void)sdp; (void)type; (void)out_answer_json;
        return false;
    } // [13]

    bool SignalClient::get_bundle(const std::string& peer_id, std::string& out_bundle_json) {
        // TODO: Реализуйте HTTP GET base_/bundle/{peer_id}, присвойте out_bundle_json тело
        (void)peer_id; (void)out_bundle_json;
        return false;
    } // [13]

} // namespace minivpn
