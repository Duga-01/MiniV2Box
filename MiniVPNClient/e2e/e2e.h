#ifndef MINIVPNCLIENT_E2E_H
#define MINIVPNCLIENT_E2E_H

#endif //MINIVPNCLIENT_E2E_H

#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <unordered_map>

using Bytes = std::vector<uint8_t>;

struct X3DHPublicBundle {
    Bytes ik_pub;    // X25519 public (32)
    Bytes spk_pub;   // X25519 public (32)
    Bytes spk_sig;   // подпись XEdDSA(ik_priv, Encode(spk_pub)) — проверка опциональна здесь
    std::optional<Bytes> opk_pub; // X25519 public (32)
};

class IE2EStore {
public:
    virtual ~IE2EStore() = default;
    virtual bool load(const std::string& path) = 0;
    virtual bool save(const std::string& path) const = 0;

    virtual void set_identity(const Bytes& ik_priv, const Bytes& ik_pub) = 0;  // X25519
    virtual bool get_identity(Bytes& ik_priv, Bytes& ik_pub) const = 0;

    // Возвращает и помечает потреблённым один OPK (priv,pub). Если пусто — false.
    virtual bool acquire_opk(Bytes& opk_priv, Bytes& opk_pub) = 0;

    // DR-полка для peer_id: сериализованное состояние
    virtual void put_session(const std::string& peer_id, const Bytes& blob) = 0;
    virtual bool get_session(const std::string& peer_id, Bytes& blob_out) const = 0;
};

struct DRMessage {
    Bytes header;     // сериализованный DR-заголовок
    Bytes ciphertext; // шифртекст
};

// Настройки/константы E2E
struct E2EParams {
    // Идентификатор для HKDF info
    std::string info = "MiniVPN-X3DH";
    // AEAD выбор для fallback (если libolm не подключён)
    bool use_chacha20poly1305_ietf = true;
    // Лимиты
    size_t max_dr_header = 4096;
    size_t max_ciphertext = 4 * 1024 * 1024;
};

class E2EClient {
public:
    E2EClient(std::string self_id, IE2EStore& store, E2EParams params = {});

    // Инициация X3DH к удалённому бандлу, формируем Root Key и запускаем DR
    bool initiate_session(const std::string& peer_id, const X3DHPublicBundle& remote);

    // Ответ (classic X3DH “respond”) требует первого сообщения инициатора — делается при первом decrypt
    // self_bundle нужен для проверки/вычисления, если требуется (например, проверить spk_sig).
    void set_self_bundle(const X3DHPublicBundle& self_bundle);

    // DR операции. AD обязателен (JSON без via, упорядочен).
    // Возвращает DRMessage (header,ciphertext) либо plaintext fallback, если DR не готов.
    DRMessage encrypt(const std::string& peer_id, const Bytes& plaintext, const Bytes& ad);
    // Принимает DRMessage. Если DR ещё не инициализирован у “responder”, пытается завершить X3DH и поднять DR.
    // Возвращает расшифрованный plaintext; std::nullopt при ошибке аутентификации.
    std::optional<Bytes> decrypt(const std::string& peer_id, const DRMessage& msg, const Bytes& ad);

    // Сохранение/восстановление DR
    bool restore_session(const std::string& peer_id);
    bool persist_session(const std::string& peer_id);

    bool ready(const std::string& peer_id) const;

private:
    std::string self_id_;
    IE2EStore& store_;
    E2EParams params_;
    std::optional<X3DHPublicBundle> self_bundle_;

    // Кэш: peer_id -> SK (Root Key) и/или сериализованное DR-состояние
    std::unordered_map<std::string, Bytes> root_keys_;
    std::unordered_map<std::string, Bytes> dr_state_;

    // Вспомогательные
    Bytes hkdf_sha256(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t L);
    Bytes x25519(const Bytes& priv32, const Bytes& pub32);
    void burn(Bytes& b);

    // DR адаптеры
    bool dr_load(const std::string& peer_id, Bytes& out);
    bool dr_save(const std::string& peer_id, const Bytes& in);
    bool dr_init_initiator(const std::string& peer_id, const Bytes& root_key);
    bool dr_init_responder(const std::string& peer_id, const Bytes& root_key, const DRMessage& first_msg, const Bytes& ad);
    DRMessage dr_encrypt(const std::string& peer_id, const Bytes& plaintext, const Bytes& ad);
    std::optional<Bytes> dr_decrypt(const std::string& peer_id, const DRMessage& msg, const Bytes& ad);
};
