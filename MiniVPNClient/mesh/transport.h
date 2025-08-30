#ifndef MINIVPNCLIENT_TRANSPORT_H
#define MINIVPNCLIENT_TRANSPORT_H

#endif //MINIVPNCLIENT_TRANSPORT_H

#pragma once
// include/minivpn/transport.hpp
#pragma once
#include "minivpn/mesh.hpp"
#include <rtc/rtc.hpp>
#include <memory>
#include <string>

namespace minivpn {

class DCAdapter : public IDataChannel {
public:
    explicit DCAdapter(std::shared_ptr<rtc::DataChannel> dc);
    void send(const uint8_t* data, size_t len) override;
    size_t bufferedAmount() const override;
    bool open() const override;
    void close() override;
private:
    std::shared_ptr<rtc::DataChannel> dc_;
};

class SignalClient {
public:
    explicit SignalClient(std::string base);
    bool post_offer(const std::string& peer_id, const std::string& sdp, const std::string& type, std::string& out_answer_json);
    bool get_bundle(const std::string& peer_id, std::string& out_bundle_json);
private:
    std::string base_;
};

} // namespace minivpn
// include/minivpn/transport.hpp
#pragma once
#include "minivpn/mesh.hpp"
#include <rtc/rtc.hpp>
#include <memory>
#include <string>

namespace minivpn {

    class DCAdapter : public IDataChannel {
    public:
        explicit DCAdapter(std::shared_ptr<rtc::DataChannel> dc);
        void send(const uint8_t* data, size_t len) override;
        size_t bufferedAmount() const override;
        bool open() const override;
        void close() override;
    private:
        std::shared_ptr<rtc::DataChannel> dc_;
    };

    class SignalClient {
    public:
        explicit SignalClient(std::string base);
        bool post_offer(const std::string& peer_id, const std::string& sdp, const std::string& type, std::string& out_answer_json);
        bool get_bundle(const std::string& peer_id, std::string& out_bundle_json);
    private:
        std::string base_;
    };

} // namespace minivpn
