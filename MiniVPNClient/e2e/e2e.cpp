// e2e.cpp
#include "minivpn/e2e.hpp"

#include <sodium.h>
#include <stdexcept>
#include <cstring>
#include <unordered_map>

// — Вспомогательные локальные функции —
namespace {
    inline void burn(minivpn::Bytes& b) { if (!b.empty()) { sodium_memzero(b.data(), b.size()); b.clear(); } }

    // HKDF-SHA256: Extract + Expand (libsodium 1.0.19+)
    minivpn::Bytes hkdf_extract(const minivpn::Bytes& salt, const minivpn::Bytes& ikm) {
        minivpn::Bytes prk(crypto_kdf_hkdf_sha256_KEYBYTES);
        if (crypto_kdf_hkdf_sha256_extract(
                prk.data(),
                salt.empty() ? nullptr : salt.data(),
                salt.size(),
                ikm.data(), ikm.size()) != 0) {
            throw std::runtime_error("hkdf extract failed");
        }
        return prk;
    }
    minivpn::Bytes hkdf_expand(const minivpn::Bytes& prk, const minivpn::Bytes& info, size_t out_len) {
        minivpn::Bytes out(out_len);
        if (crypto_kdf_hkdf_sha256_expand(
                out.data(), out.size(),
                reinterpret_cast<const char*>(info.data()), info.size(),
                prk.data()) != 0) {
            throw std::runtime_error("hkdf expand failed");
        }
        return out;
    }

    // X25519 (Curve25519) DH
    minivpn::Bytes x25519(const minivpn::Bytes& priv32, const minivpn::Bytes& pub32) {
        if (priv32.size()!=crypto_scalarmult_SCALARBYTES || pub32.size()!=crypto_scalarmult_BYTES)
            throw std::invalid_argument("x25519 key size");
        minivpn::Bytes out(crypto_scalarmult_BYTES);
        if (crypto_scalarmult(out.data(), priv32.data(), pub32.data()) != 0) {
            throw std::runtime_error("x25519 failed");
        }
        return out;
    }

    // AEAD ChaCha20-Poly1305 IETF
    struct AEAD {
        static constexpr size_t NPUB = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
        static constexpr size_t ABYTES = crypto_aead_chacha20poly1305_ietf_ABYTES;

        static minivpn::Bytes nonce() { minivpn::Bytes n(NPUB); randombytes_buf(n.data(), n.size()); return n; }

        static minivpn::Bytes encrypt(const minivpn::Bytes& key32, const minivpn::Bytes& nonce12,
                                      const minivpn::Bytes& pt, const minivpn::Bytes& ad) {
            minivpn::Bytes ct(pt.size() + ABYTES);
            unsigned long long clen = 0;
            if (crypto_aead_chacha20poly1305_ietf_encrypt(
                    ct.data(), &clen,
                    pt.data(), pt.size(),
                    ad.data(), ad.size(),
                    nullptr,
                    nonce12.data(), key32.data()) != 0) {
                throw std::runtime_error("aead encrypt failed");
            }
            ct.resize(clen);
            return ct;
        }

        static minivpn::Bytes decrypt(const minivpn::Bytes& key32, const minivpn::Bytes& nonce12,
                                      const minivpn::Bytes& ct, const minivpn::Bytes& ad) {
            if (ct.size()<ABYTES) throw std::runtime_error("aead ct too short");
            minivpn::Bytes pt(ct.size() - ABYTES);
            unsigned long long plen = 0;
            if (crypto_aead_chacha20poly1305_ietf_decrypt(
                    pt.data(), &plen,
                    nullptr,
                    ct.data(), ct.size(),
                    ad.data(), ad.size(),
                    nonce12.data(), key32.data()) != 0) {
                throw std::runtime_error("aead decrypt failed");
            }
            pt.resize(plen);
            return pt;
        }
    };
} // namespace

namespace minivpn {

E2EClient::E2EClient(std::string self_id, IE2EStore& store, E2EParams params)
    : self_id_(std::move(self_id)), store_(store), params_(params) {
    if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
} // [10]

bool E2EClient::initiate_session(const std::string& peer_id, const X3DHPublicBundle& remote) {
    Bytes ik_priv, ik_pub;
    if (!store_.get_identity(ik_priv, ik_pub)) return false;

    // Эфемерная пара EKa
    Bytes eka_priv(crypto_box_SECRETKEYBYTES), eka_pub(crypto_box_PUBLICKEYBYTES);
    crypto_box_keypair(eka_pub.data(), eka_priv.data());

    // X3DH: DH1..DH4
    Bytes dh1 = x25519(ik_priv, remote.spk_pub);
    Bytes dh2 = x25519(eka_priv, remote.ik_pub);
    Bytes dh3 = x25519(eka_priv, remote.spk_pub);
    Bytes dh4;
    if (remote.opk_pub) dh4 = x25519(eka_priv, *remote.opk_pub);

    // IKM и HKDF (extract + expand)
    Bytes ikm; ikm.reserve(dh1.size()+dh2.size()+dh3.size()+dh4.size());
    ikm.insert(ikm.end(), dh1.begin(), dh1.end());
    ikm.insert(ikm.end(), dh2.begin(), dh2.end());
    ikm.insert(ikm.end(), dh3.begin(), dh3.end());
    if (!dh4.empty()) ikm.insert(ikm.end(), dh4.begin(), dh4.end());

    Bytes salt(crypto_kdf_hkdf_sha256_KEYBYTES, 0x00); // допускается нулевой salt
    Bytes prk = hkdf_extract(salt, ikm);
    Bytes info_b(params_.info.begin(), params_.info.end());
    Bytes root_key = hkdf_expand(prk, info_b, 32);

    burn(ikm); burn(dh1); burn(dh2); burn(dh3); burn(dh4); burn(eka_priv); burn(prk);

    // DR init (инициатор): в fallback храним ключ напрямую, готово для замены на libolm
    if (root_key.size()!=32) return false;
    dr_state_[peer_id] = root_key;
    root_keys_[peer_id] = root_key;
    return persist_session(peer_id);
} // [10]

void E2EClient::set_self_bundle(const X3DHPublicBundle& self_bundle) { self_bundle_ = self_bundle; } // [10]

bool E2EClient::restore_session(const std::string& peer_id) {
    Bytes blob;
    if (!store_.get_session(peer_id, blob)) return false;
    if (blob.size()!=32) return false;
    dr_state_[peer_id] = blob;
    root_keys_[peer_id] = blob;
    return true;
} // [10]

bool E2EClient::persist_session(const std::string& peer_id) {
    auto it = dr_state_.find(peer_id);
    if (it == dr_state_.end()) return false;
    store_.put_session(peer_id, it->second);
    return true;
} // [10]

bool E2EClient::ready(const std::string& peer_id) const { return dr_state_.find(peer_id) != dr_state_.end(); } // [10]

DRMessage E2EClient::encrypt(const std::string& peer_id, const Bytes& plaintext, const Bytes& ad) {
    if (plaintext.size() > params_.max_ciphertext) throw std::runtime_error("plaintext too large");
    auto it = dr_state_.find(peer_id);
    if (it == dr_state_.end()) {
        return DRMessage{Bytes{}, plaintext};
    }
    const Bytes& key = it->second; // 32
    Bytes nonce = AEAD::nonce();
    Bytes ct = AEAD::encrypt(key, nonce, plaintext, ad);
    if (nonce.size() > params_.max_dr_header) throw std::runtime_error("dr header too large");
    return DRMessage{nonce, ct};
} // [10]

std::optional<Bytes> E2EClient::decrypt(const std::string& peer_id, const DRMessage& msg, const Bytes& ad) {
    if (msg.header.empty()) return std::nullopt;
    if (msg.header.size() > params_.max_dr_header || msg.ciphertext.size() > params_.max_ciphertext)
        return std::nullopt;

    auto it = dr_state_.find(peer_id);
    if (it == dr_state_.end()) return std::nullopt;
    const Bytes& key = it->second;

    try {
        auto pt = AEAD::decrypt(key, msg.header, msg.ciphertext, ad);
        return pt;
    } catch (...) {
        return std::nullopt;
    }
} // [10]

} // namespace minivpn
