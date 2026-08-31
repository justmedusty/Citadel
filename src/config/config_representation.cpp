//
// Created by dustyn on 6/14/26.
//

#include "config_representation.h"
#include "crypt/encryption.h"


#include <fstream>
#include <string>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif

std::filesystem::path ConfigRepresentation::get_home_directory() {
#ifdef _WIN32
    // Windows: use USERPROFILE or HOMEDRIVE+HOMEPATH
    const char *userProfile = std::getenv("USERPROFILE");
    if (userProfile) std::filesystem::path(userProfile) / homePath / ".vault" / "citadel.vault";

    const char *homeDrive = std::getenv("HOMEDRIVE");
    const char *homePath = std::getenv("HOMEPATH");
    if (homeDrive && homePath) {
        return std::filesystem::path(homeDrive) / homePath / ".vault" / "citadel.vault";
    }


    throw std::runtime_error("Cannot determine home directory on Windows");
#else
    // Unix/macOS: prefer HOME env var, fall back to passwd entry
    const char *home = std::getenv("HOME");
    if (home) return std::filesystem::path(home) / ".citadel" / "citadel.vault";

    // Fallback: look up the real home from the password database
    struct passwd *pw = getpwuid(getuid());
    if (!pw) {
        throw std::runtime_error("Could not get home directory");
    }

    auto path = std::filesystem::path(pw->pw_dir) / ".citadel" / "citadel.vault";
    return path;
#endif
}


void ConfigRepresentation::parse_command_line_args(std::vector<std::string> arguments) {
    bool ls = false;
    bool loglevel_set = false;
    bool delete_key = false;
    bool rekey = false;
    bool decrypt_all = false;
    bool decrypt_many = false;
    bool defcon_set = false;
    std::set<std::string> keys;
    //Set a default value if the user does not specify it will go to defcon5
    this->defcon = Defcon::DEFCON5;

    for (auto arg = arguments.begin(); arg != arguments.end(); ++arg) {

        if (*arg == FLAG_HELP) {
            help();
        }

        if (*arg == FLAG_LIST_ALL_KEYS) {
            //we do not list it right away since they may pass us a different vault file via a commandline option instead of the default vault file, we do it
            //after parsing
            ls = true;
            continue;
        }

        if (*arg == FLAG_DECRYPT_MANY_KEYS) {
            decrypt_many = true;

            if (arg == arguments.end()) {
                std::cerr << "You passed " << FLAG_DECRYPT_MANY_KEYS << " without any keys, this is invalid." <<
                        std::endl;
                exit(1);
            }

            while (++arg != arguments.end() && *arg != FLAG_DEFCON_LEVEL_TO_ENCRYPT) {
                logger.log(LogLevel::DEBUG, "parse_command_line_args()", "Pushing back arg...");
                keys.insert(*arg);
            }

            if (arg == arguments.end()) {
                std::cerr <<
                        "You must specify the defcon level for multientry decryption for correctness purposes and to prevent bugs"
                        << std::endl;
                exit(1);
            }
        }

        if (*arg == FLAG_DELETE_KEY) {
            delete_key = true;
            continue;
        }


        if (*arg == FLAG_LOG_LEVEL) {
            auto loglevel = *++arg;
            if (loglevel == "debug") {
                logger.set_loglevel(LogLevel::DEBUG);
            } else if (loglevel == "info") {
                logger.set_loglevel(LogLevel::INFO);
            } else if (loglevel == "warn") {
                logger.set_loglevel(LogLevel::WARN);
            } else if (loglevel == "error") {
                logger.set_loglevel(LogLevel::ERROR);
            } else if (loglevel == "critical") {
                logger.set_loglevel(LogLevel::CRITICAL);
            } else {
                logger.set_loglevel(LogLevel::ERROR);
            }
            loglevel_set = true;
            continue;
        }

        if ((*arg) == FLAG_ENCRYPT) {
            this->decrypt = false;
            continue;
        }

        if ((*arg) == FLAG_DECRYPT) {
            this->decrypt = true;
            continue;
        }

        if (*arg == FLAG_REPASS_DEFCON_LEVEL) {
            rekey = true;
        }

        if (*arg == FLAG_DEFCON_LEVEL_TO_ENCRYPT || *arg == FLAG_REPASS_DEFCON_LEVEL) {
            if (arg == arguments.end()) {
                std::cerr <<
                        "You have passed a flag that requires a value, with no value given! You must provide a value when using the "
                        << FLAG_VALUE << " flag." << std::endl;
            }
            ++arg;

            /*
             *  The way we are parsing this is forgiving , 12434534 would be 1 , 23453456, would be 2 etc.
             */
            defcon_set = true;
            switch (arg->data()[0]) {
                case '1':
                    this->defcon = Defcon::DEFCON1;
                    break;
                case '2':
                    this->defcon = Defcon::DEFCON2;
                    break;
                case '3':
                    this->defcon = Defcon::DEFCON3;
                    break;
                case '4':
                    this->defcon = Defcon::DEFCON4;
                    break;
                case '5':
                    this->defcon = Defcon::DEFCON5;
                    break;
                default:
                    std::cerr << *arg << " is an invalid defcon value, {1,2,3,4,5} are the valid values." << std::endl;
                    /*
                     * We may want to cleanse all of these arg values in case user passes something sensitive accidentally, but for now we won't
                     */
                    exit(1);
            }
            continue;
        }

        if (*arg == FLAG_VALUE) {
            if (arg == arguments.end()) {
                std::cerr <<
                        "You have passed a flag that requires a value, with no value given! You must provide a value when using the "
                        << FLAG_VALUE << " flag." << std::endl;
            }
            this->value = std::move(*(arg + 1));
            ++arg;
            continue;
        }

        if (*arg == FLAG_ENCRYPTION_ALGORITHM) {
            std::cout << "Encryption algorithm: this option is not yet supported. AES 256 CBC only. " << std::endl;
            exit(1);
        }

        if (*arg == FLAG_KEY) {
            if (arg == arguments.end()) {
                std::cerr <<
                        "You have passed a flag that requires a value, with no value given! You must provide a value when using the "
                        << FLAG_KEY << " flag." << std::endl;
            }
            this->key = std::move(*(arg + 1));
            ++arg;
            continue;
        }

        if (*arg == FLAG_VAULT_FILE_LOCATION) {
            if (arg == arguments.end()) {
                std::cerr <<
                        "You have passed a flag that requires a value, with no value given! You must provide a value when using the "
                        << FLAG_VAULT_FILE_LOCATION << " flag." << std::endl;
            }
            this->vault_file_path = std::move(*(arg + 1));
            ++arg;
            continue;
        }

        if (*arg == FLAG_DECRYPT_ALL_KEYS) {
            if (arg == arguments.end()) {
                std::cerr <<
                        "You have passed a flag that requires a value, with no value given! You must provide a value when using the "
                        << FLAG_DECRYPT_ALL_KEYS << " flag." << std::endl;
            }

            decrypt_all = true;
        }
    }


    if (!this->vault_file_path.empty() && !std::filesystem::exists(this->vault_file_path)) {
        std::cout << "No vault file exists at location : " << this->vault_file_path << " , creating a new vault..." <<
                std::endl;   void receive_passphrase();
        create_vault(this->vault_file_path);
    }

    if (ls) {
        list_all_entries(*this);
    }


    if (!loglevel_set) {
        logger.set_loglevel(LogLevel::ERROR);
    }


    if (rekey) {
        Encryption::EncryptionContext encryption_context(*this);
        Encryption::EncryptionContext decryption_context(*this);
        rekey_defcon_level(this->defcon, *this, decryption_context, decryption_context);
    }

    if (decrypt_many == true) {
        if (defcon_set == false) {
            std::cerr <<
                    "When decrypting many, to prevent odd behavior, you must specify the defcon level. It is not specified."
                    << std::endl;
            exit(1);
        }

        Encryption::EncryptionContext decryption_context(*this);
        auto values = read_many_entries(keys, *this);
        handle_value_list(values, decryption_context);
    }

    if (decrypt_all == true) {
        if (defcon_set == false) {
            std::cerr <<
                    "When decrypting many, to prevent odd behavior, you must specify the defcon level. It is not specified."
                    << std::endl;
            exit(1);
        }
        Encryption::EncryptionContext decryption_context(*this);
        auto values = read_all_entries(*this);
        handle_value_list(values, decryption_context);
    }

    if (this->key.empty()) {
        std::cerr << "You have not specified a key! You must provide a key! Try citadel -h for help!" << std::endl;
        exit(1);
    }

    if (delete_key == true) {
        delete_entry(key, *this);
    }


    if (this->decrypt == false && this->value.empty()) {
        if (!this->value.empty()) {
            //cleanse that shit
            OPENSSL_cleanse(this->value.data(), this->value.size());
        }
        std::cerr <<
                "You have not specified a value and are trying to encrypt! You must provide a value! Try citadel -h for help!"
                <<
                std::endl;
        exit(1);
    }
}

