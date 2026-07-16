//
// Created by dustyn on 6/14/26.
//

#ifndef CITADEL_ENCRYPTION_H
#define CITADEL_ENCRYPTION_H
#include <string>
#include <vector>
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "config/config_representation.h"
#include <unistd.h>
#include "base64.h"
#include "algo/aes.h"

/*
 *  Putting as a note for now
 *  The ciphertext will be : 16 BYTE KDF SALT | 12 BYTE AES-256-GCM IV | 16 BYTE AES-256-GCM AEAD TAG | CIPHERTEXT + padding
 */
namespace Encryption {
    void lock_memory();

    struct EncryptionContext {
        std::string passphrase;
        std::string confirm_passphrase; //only for setting a defcon section password to ensure you typed it correctly
        std::vector<std::byte> key_material;
        std::vector<std::byte> iv;
        std::vector<uint8_t> kdf_salt;
        std::string secret;
        std::string defcon_signature;
        Defcon current_defcon;
        EncryptionMode mode;
        ConfigRepresentation configRepresentation;

        void receive_passphrase();

        void decrypt_string(const std::string &ciphertext);

        std::string generate_signature();

        std::string encrypt_string();

        bool verify_defcon_signature();

        explicit EncryptionContext(const ConfigRepresentation &config) {
            this->current_defcon = config.defcon;
            this->configRepresentation = config;
            this->passphrase = "";
            this->confirm_passphrase = "";
            this->key_material = std::vector<std::byte>(32);
            this->iv = std::vector<std::byte>(AES_GCM_IV_LEN);
            this->mode = EncryptionMode::AES_256_GCM; //Default algo
            this->secret = config.value;
            this->defcon_signature = "";
        }

        ~EncryptionContext() {
            logger.log(INFO, "~EncryptionContext()", "Secure destruction initialized...");
            OPENSSL_cleanse(this->passphrase.data(), this->passphrase.size());
            OPENSSL_cleanse(this->confirm_passphrase.data(), this->confirm_passphrase.size());
            OPENSSL_cleanse(this->key_material.data(), this->key_material.size());
            OPENSSL_cleanse(this->secret.data(), this->secret.size());
        }

    private:
        void receive_confirm_passphrase();
        void generate_iv();
        [[nodiscard]] std::string get_signature() const;
    };
};
#endif //CITADEL_ENCRYPTION_H
