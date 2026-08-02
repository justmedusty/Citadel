//
// Created by dustyn on 6/14/26.
//

#include "encryption.h"

#include <fstream>
#include <iostream>
#include <ostream>
#include <string>
#if defined(_POSIX_VERSION) && _POSIX_VERSION >= 200112L
#include <sys/mman.h>
#endif
#include <cstring>
#include <math.h>
#include <openssl/rand.h>
#include "log/log.h"
#include "base64.h"
#include "key_derivation.h"
#include "algo/aes.h"
#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
namespace Encryption {
    /*
     *  This SHOULDNt be an issue generally speaking for an application like this that just runs does something interactive then exits, but
     *  we should be cautious anyway and ensure that it cannot be paged to disk with sensitive key material or plaintext password.
     */
    void lock_memory() {
#if defined(_POSIX_VERSION) && _POSIX_VERSION >= 200112L
        //THIS SHOULD HAVE MCL_CURRENT AND MCL_FUTURE FOR NOW JUST MCL FUTURE SINCE IT NEEDS ADDDED CAPS FOR BOTH
        if (mlockall(MCL_FUTURE) < 0) {
            // lock all current and future pages into main memory
            logger.log(ERROR, "lock_memory()",
                       "mlockall failed, exiting early for security purposes. Check memory availability/consumption and try again.");
            exit(1);
        }

#elif defined(_WIN32)
        VirtualLock(ptr, size);
        return 1;
#else
        logger.log(ERROR, "lock_memory()",
                   "Memory lock cannot be attained as this program is neither POSIX nor WIN32, this is not a massive risk since this program is short lived, but paging to disk can compromise program security");
        return 0;
#endif
    }

    //Check if we are actually in a terminal environment
    bool stdin_terminal() {
#ifdef WIN32
        return _isatty(_fileno(stdin));
#else
        return isatty(fileno(stdin));
#endif
    }

    void set_stdin_echo(bool enable) {
        if (!stdin_terminal()) {
            logger.log(WARN, "set_stdin_echo()",
                       "stdin is NOT a terminal, this is not standard usage of this application");
            return;
        }
#ifdef WIN32
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode;
        if (!GetConsoleMode(hStdin, &mode)) {
            fputs("GetConsoleMode failed\n", stderr);
            return;
        }
        if (!enable) {
            mode &= ~ENABLE_ECHO_INPUT;
        } else {
            mode |= ENABLE_ECHO_INPUT;
        }
        if (!SetConsoleMode(hStdin, mode)) {
            fputs("SetConsoleMode failed\n", stderr);
        }
#else
        termios tty;
        if (tcgetattr(STDIN_FILENO, &tty) != 0) {
            logger.log(ERROR, "stdin_terminal()", "tcgetattr failed");
            return;
        }
        if (!enable) {
            tty.c_lflag &= static_cast<decltype(tty.c_lflag)>(~ECHO);
        } else {
            tty.c_lflag |= ECHO;
        }
        if (tcsetattr(STDIN_FILENO, TCSANOW, &tty) != 0) {
            logger.log(ERROR, "stdin_terminal()", "tcsetattr failed");
        }
#endif
    }

    void EncryptionContext::generate_iv() {
        auto iv_ptr = reinterpret_cast<unsigned char *>(this->iv.data());
        RAND_bytes(iv_ptr, AES_GCM_IV_LEN);
    }

    std::string EncryptionContext::get_signature() const {
        std::string signature;
        std::string defcon;

        switch (this->current_defcon) {
            case Defcon::DEFCON1:
                defcon = std::string{CITADEL_DEFCON_1};
                break;
            case Defcon::DEFCON2:
                defcon = std::string{CITADEL_DEFCON_2};
                break;
            case Defcon::DEFCON3:
                defcon = std::string{CITADEL_DEFCON_3};
                break;
            case Defcon::DEFCON4:
                defcon = std::string{CITADEL_DEFCON_4};
                break;
            case Defcon::DEFCON5:
                defcon = std::string{CITADEL_DEFCON_5};
                break;
            default:
                return "";
        }

        std::ifstream vault(this->configRepresentation.vault_file_path);

        std::string line;
        bool here = false;
        while (std::getline(vault, line)) {
            if (line.contains(defcon)) {
                here = true;
                continue;
            }

            if (here) {
                if (!line.starts_with(CITADEL_VAULT_SIG_START)) {
                    logger.log(WARN, "get_signature()", "Cannot find a valid signature in vault file");
                    return "";
                }
                std::string sig = line.substr(sizeof(CITADEL_VAULT_SIG_START) - 1,
                                              line.length() - (
                                                  (sizeof(CITADEL_VAULT_SIG_END) + sizeof(CITADEL_VAULT_SIG_START)) -
                                                  2));

                std::cout << "SIG FETCHED IS " << sig << std::endl;
                logger.log(INFO, "get_signature()",
                           std::format("Fetching signature for DEFCON{} , signature is : {}",
                                       static_cast<int>(current_defcon), *sig.c_str()));
                return sig;
            }
        }
        logger.log(CRITICAL, "get_signature()",
                   "End of get_signature reached, this is a major bug! Please report to developer");
        return "";
    }

    bool EncryptionContext::verify_defcon_signature(std::optional<std::string> signature) {
        std::string expected = CITADEL_ENCRYPTION_STRING;
        std::string sig = this->get_signature();
        std::string decoded_signature = Base64::base64_decode(sig);
        std::string salt = decoded_signature.substr(0,KDF_SALT_SIZE_BYTES);
        std::string iv = decoded_signature.substr(KDF_SALT_SIZE_BYTES, AES_GCM_IV_LEN);
        std::string tag = decoded_signature.substr(KDF_SALT_SIZE_BYTES + AES_GCM_IV_LEN, AES_GCM_AEAD_TAG_SIZE);
        std::string cipherttxt = decoded_signature.substr(KDF_SALT_SIZE_BYTES + AES_GCM_IV_LEN + AES_GCM_AEAD_TAG_SIZE,
                                                          decoded_signature.length());


        logger.log(DEBUG, "decrypt_string()", "Finishing cleaning up salt, iv, tag, ciphertext...");

        std::vector<uint8_t> salt_vec(salt.begin(), salt.end());


        derive_key(this->passphrase, salt_vec, this->key_material, this->current_defcon);


        int i = 0;
        for (const auto &c: iv) {
            this->iv[i++] = static_cast<std::byte>(c);
        }

        this->secret.resize(cipherttxt.length());

        //This can be hardcoded to 50 because the sig string is hardcoded and known in advance
        std::string plaintext(50, '\0');
        //giving extra just in case, we will just check the expected size from 0 offset


        int plaintext_len = 50;
        const auto plaintext_ptr = reinterpret_cast<unsigned char *>(plaintext.data());
        const auto *ciphertext_ptr = reinterpret_cast<unsigned char *>(cipherttxt.data());
        const auto tag_ptr = reinterpret_cast<unsigned char *>(tag.data());
        const auto key_ptr = reinterpret_cast<unsigned char *>(this->key_material.data());

        const auto ret = (aes_256_gcm_decrypt(ciphertext_ptr, cipherttxt.length(), key_ptr,
                                             reinterpret_cast<const unsigned char *>(iv.c_str()), plaintext_ptr,
                                             plaintext_len, tag_ptr) == 1);

        if (ret != 1) {
            logger.log(ERROR, "verify_defcon_signature()",
                       "Encryption verification failed");
            return false;
        }

        if (!plaintext.contains(expected)) {
            logger.log(ERROR, "verify_defcon_signature()",
                       "Expected does NOT equal plaintext");
            return false;
        }

        this->secret.clear();
        return true;
    }


    void EncryptionContext::decrypt_string(const std::string &ciphertext) {
        std::string decoded = Base64::base64_decode(ciphertext);
        std::string salt = decoded.substr(0,KDF_SALT_SIZE_BYTES);
        std::string iv = decoded.substr(KDF_SALT_SIZE_BYTES, AES_GCM_IV_LEN);
        std::string tag = decoded.substr(KDF_SALT_SIZE_BYTES + AES_GCM_IV_LEN, AES_GCM_AEAD_TAG_SIZE);
        std::string cipherttxt = decoded.substr(KDF_SALT_SIZE_BYTES + AES_GCM_IV_LEN + AES_GCM_AEAD_TAG_SIZE,
                                                decoded.length());

        logger.log(DEBUG, "decrypt_string()", "Finishing cleaning up salt, iv, tag, ciphertext...");

        std::vector<uint8_t> salt_vec(salt.begin(), salt.end());


        derive_key(this->passphrase, salt_vec, this->key_material, this->current_defcon);


        int i = 0;
        for (const auto &c: iv) {
            this->iv[i++] = static_cast<std::byte>(c);
        }

        this->secret.resize(cipherttxt.length());

        const auto plaintext_ptr = reinterpret_cast<unsigned char *>(this->secret.data());
        const auto ciphertext_ptr = reinterpret_cast<unsigned char *>(cipherttxt.data());
        const auto tag_ptr = reinterpret_cast<unsigned char *>(tag.data());
        const auto key_ptr = reinterpret_cast<unsigned char *>(this->key_material.data());
        const auto iv_ptr = reinterpret_cast<unsigned char *>(this->iv.data());

        int plaintext_len = cipherttxt.length();
        logger.log(DEBUG, "decrypt_string()", "Calling into aes_256_gcm_decrypt...");
        auto ret = aes_256_gcm_decrypt(ciphertext_ptr, cipherttxt.size(), key_ptr, iv_ptr, plaintext_ptr, plaintext_len,
                                       tag_ptr);
        logger.log(DEBUG, "decrypt_string()", "Returned from aes_256_gcm_decrypt...");

        if (!ret) {
            std::cerr << "Decryption failed" << std::endl;
            exit(1);
        }


    }

    std::string EncryptionContext::generate_signature() {
        std::cout <<
                "You must set the password for this section of the vault, please type your password, and then confirm it. This will be checked against for any new entries you write in this vault section to ensure consistency"
                << std::endl;
        receive_passphrase();
        receive_confirm_passphrase();

        if (this->passphrase != this->confirm_passphrase) {
            std::cerr << "Your passwords do NOT match, cannot generate signature..." << std::endl;
            delete this;
            exit(1);
        }

        this->secret = CITADEL_ENCRYPTION_STRING;
        return this->encrypt_string();
    }

    std::string EncryptionContext::encrypt_string() {
        generate_iv();
        generate_salt(this->kdf_salt);
        auto ret = derive_key(this->passphrase, this->kdf_salt, this->key_material, this->current_defcon);

        if (ret != 1) {
            logger.log(ERROR, "encrypt_string()", "An error occurred while trying to derive key");
            delete this;
            exit(1);
        }

        std::string ciphertext(
            this->secret.length() + 16
            /* Just make sure we have room for padding if it cant be split into AES blocks nicely*/, '\0');

        int ciphertext_len = ciphertext.size();
        std::string tag(AES_GCM_AEAD_TAG_SIZE, '\0');
        ret = aes_256_gcm_encrypt(reinterpret_cast<unsigned char *>(this->secret.data()), this->secret.size(),
                                  reinterpret_cast<const unsigned char *>(this->key_material.data()),
                                  reinterpret_cast<const unsigned char *>(this->iv.data()),
                                  reinterpret_cast<unsigned char *>(ciphertext.data()), &ciphertext_len,
                                  reinterpret_cast<unsigned char *>(tag.data()));

        if (!ret) {
            logger.log(ERROR, "encrypt_string()", "aes_256_gcm_encrypt call has failed");
            delete this;
            exit(1);
        }

        std::string *kdf_salt = reinterpret_cast<std::string *>(this->kdf_salt.data());

        ciphertext.resize(ciphertext_len);

        std::string final_payload;
        final_payload.reserve(this->kdf_salt.size() + this->iv.size() + tag.size() + ciphertext.length());
        final_payload.append(reinterpret_cast<char *>(this->kdf_salt.data()), this->kdf_salt.size());
        final_payload.append(reinterpret_cast<char *>(this->iv.data()), this->iv.size());
        final_payload.append(tag);
        final_payload.append(ciphertext);

        return Base64::base64_encode(final_payload);
    }


    void EncryptionContext::receive_passphrase() {
        if (!stdin_terminal()) {
            return;
            // This is for testing purposes for now but may be good from preventing the wrong use of this application
        }
        set_stdin_echo(false);
        std::string current_DEFCON;

        std::cout << "Please enter your password, the DEFCON level password you must provide is DEFCON" << static_cast<
                    int>(this->current_defcon) <<
                std::endl;

        std::cin >> passphrase;

        set_stdin_echo(true);
    }


    void EncryptionContext::receive_confirm_passphrase() {
        if (!stdin_terminal()) {
            return;
            // This is for testing purposes for now but may be good from preventing the wrong use of this application
        }
        set_stdin_echo(false);
        std::string current_DEFCON;

        std::cout << "Please confirm your password, the DEFCON level password you must provide is DEFCON" << static_cast
                <
                    int>(this->current_defcon) <<
                std::endl;

        std::cin >> confirm_passphrase;

        set_stdin_echo(true);
    }
};
