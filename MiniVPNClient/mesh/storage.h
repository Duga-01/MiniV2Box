#ifndef MINIVPNCLIENT_STORAGE_H
#define MINIVPNCLIENT_STORAGE_H

#endif //MINIVPNCLIENT_STORAGE_H

#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace minivpn {

    using Bytes = std::vector<uint8_t>;

    class IE2EStore {
    public:
        virtual ~IE2EStore() = default;
        virtual bool load(const std::string& path) = 0;
        virtual bool save(const std::string& path) const = 0;

        virtual void set_identity(const Bytes& ik_priv, const Bytes& ik_pub) = 0;  // X25519
        virtual bool get_identity(Bytes& ik_priv, Bytes& ik_pub) const = 0;

        // Возврат и потребление OPK (X25519). false если пусто
        virtual bool acquire_opk(Bytes& opk_priv, Bytes& opk_pub) = 0;

        // DR состояния
        virtual void put_session(const std::string& peer_id, const Bytes& blob) = 0;
        virtual bool get_session(const std::string& peer_id, Bytes& blob_out) const = 0;
    };

} // namespace minivpn
