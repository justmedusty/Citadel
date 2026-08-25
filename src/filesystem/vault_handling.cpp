//
// Created by dustyn on 6/16/26.
//

#include <fstream>

#include <iostream>
#include "config/config_representation.h"
#include "vault_handling.h"
#include <string>
#include <algorithm>
#include <cstring>
#include <boost/mpl/aux_/na_fwd.hpp>

#include "crypt/encryption.h"

std::string defcon_level_to_string(const Defcon defcon) {
    switch (defcon) {
        case Defcon::DEFCON1:
            return CITADEL_DEFCON_1;
        case Defcon::DEFCON2:
            return CITADEL_DEFCON_2;
        case Defcon::DEFCON3:
            return CITADEL_DEFCON_3;
        case Defcon::DEFCON4:
            return CITADEL_DEFCON_4;
        case Defcon::DEFCON5:
            return CITADEL_DEFCON_5;
    };

    logger.log(LogLevel::ERROR, "defcon_level_to_string",
               "function called with an unset defcon variable! This is invalid behavior.");
    exit(1);
}

std::string get_defcon_signature(std::string &vault_file_path, Defcon defcon) {
    std::ifstream vault(vault_file_path);
    if (!vault.is_open()) {
        std::cerr << "Could not open vault file : " << vault_file_path << std::endl;
        exit(1);
    }
    Defcon current_defcon = {};
    std::string line;
    while (std::getline(vault, line)) {
        if (line == CITADEL_DEFCON_1) {
            current_defcon = Defcon::DEFCON1;
            continue;
        }

        if (line == CITADEL_DEFCON_2) {
            current_defcon = Defcon::DEFCON2;
            continue;
        }

        if (line == CITADEL_DEFCON_3) {
            current_defcon = Defcon::DEFCON3;
            continue;
        }
        if (line == CITADEL_DEFCON_4) {
            current_defcon = Defcon::DEFCON4;
            continue;
        }
        if (line == CITADEL_DEFCON_5) {
            current_defcon = Defcon::DEFCON5;
            continue;
        }

        if (line.starts_with(CITADEL_VAULT_SIG_START) && current_defcon == defcon) {
            return line.substr(sizeof(CITADEL_VAULT_SIG_START),
                               line.size() - sizeof(CITADEL_VAULT_SIG_START) - sizeof(CITADEL_VAULT_SIG_END));
        }
    }

    return "";
}

int8_t is_vault_setup(std::filesystem::path &vault_file_path) {
    int8_t bitmap = 0;
    std::ifstream vault(vault_file_path);
    if (!vault.is_open()) {
        std::cerr << "Could not open vault file : " << vault_file_path << std::endl;
        exit(1);
    }

    std::string line;
    int found = 0;
    int sig = 0;

    while (std::getline(vault, line)) {
        if (line.starts_with('<')) {
            if (line == CITADEL_DEFCON_1) {
                found++;
                continue;
            }

            if (line == CITADEL_DEFCON_2) {
                found++;
                continue;
            }

            if (line == CITADEL_DEFCON_3) {
                found++;
                continue;
            }

            if (line == CITADEL_DEFCON_4) {
                found++;
                continue;
            }

            if (line == CITADEL_DEFCON_5) {
                found++;
                continue;
            }
        }

        //This could cause a bug if there was somehow a sig without a defcon header but that is not possible from application vault setup only manual vault fuckery
        if (line.starts_with(CITADEL_VAULT_SIG_START)) {
            bitmap |= (1 << (found - 1));
            sig++;
        }
    }

    if (found > 0 && found != 5) {
        std::cerr << vault_file_path <<
                " contains a vault file, but it is invalid! You will need to fix it or reset your vault!" <<
                std::endl;
        return -1;
    }

    if (found > 0 || sig > 0) {
        logger.log(LogLevel::INFO, "is_vault_setup()",
                   "Not all defcon levels have an associated verification signature. This will not prevent this program from running, but you will need to set a password for any DEFCON section without an associated signature."
        );
    }
    std::cout << bitmap << std::endl;
    return bitmap;
}

void write_entry(std::string &key, std::string &value, ConfigRepresentation &config) {
    std::ifstream vault(config.vault_file_path);
    if (!vault.is_open()) {
        std::cerr << "Could not open vault file: " << config.vault_file_path << std::endl;
        exit(1);
    }

    if (std::filesystem::file_size(config.vault_file_path) > MAXIMUM_VAULT_SIZE) {
        std::cerr << std::filesystem::file_size(config.vault_file_path)
                << " is too large for Citadel to handle. Please investigate." << std::endl;
        exit(1);
    }

    std::filesystem::path temp_path = config.vault_file_path;
    temp_path += ".tmp";
    std::ofstream temp(temp_path);
    if (!temp.is_open()) {
        std::cerr << "Could not create temp file" << std::endl;
        exit(1);
    }

    std::string line;

    auto current_defcon = config.defcon;

    auto target_string = defcon_level_to_string(current_defcon);

    bool found = false;
    bool done = false;

    while (std::getline(vault, line)) {
        std::string k = line.substr(0, line.find('='));
        if (k == key) {
            std::cerr << k << " clashes with your new key : " << key << ". Aborting." << std::endl;
            exit(1);
        }

        if (done) {
            temp << line << std::endl;
            continue;
        }

        if (line == target_string) {
            found = true;
        }
        if (found && line.starts_with(CITADEL_VAULT_SIG_START)) {
            temp << line << std::endl;
            temp << key << '=' << value << std::endl;
            done = true;
            continue;
        }
        temp << line << std::endl;
    }


    vault.close();
    temp.close();

    std::filesystem::remove(config.vault_file_path);
    std::filesystem::rename(temp_path, config.vault_file_path);
}

//An invariant of this function is that there is NOT an existing signature, this is a bug if this is ever called and a signature already exists.
void write_signature(std::string &signature, Defcon defcon, ConfigRepresentation &config) {
    std::string decfon_string = defcon_level_to_string(defcon);

    std::ifstream vault(config.vault_file_path);

    if (!vault.is_open()) {
        std::cerr << "Could not open vault file: " << config.vault_file_path << std::endl;
        exit(1);
    }

    if (std::filesystem::file_size(config.vault_file_path) > MAXIMUM_VAULT_SIZE) {
        std::cerr << std::filesystem::file_size(config.vault_file_path)
                << " is too large for Citadel to handle. Please investigate." << std::endl;
        exit(1);
    }

    std::filesystem::path temp_path = config.vault_file_path;
    temp_path += ".tmp";
    std::ofstream temp(temp_path);
    if (!temp.is_open()) {
        std::cerr << "Could not create temp file" << std::endl;
        exit(1);
    }

    std::string line;
    bool found = false;

    while (std::getline(vault, line)) {
        if (line.contains(decfon_string)) {
            found = true;
            temp << line << std::endl;
        }


        /*
         *  This will trip right after the defcon level which is what we want to do
         *  <DEFCON1>
         *  <-- sig=yoursignaturehere -->
         *
         *  This signature is your anchor of truth for the password for the whole section, it just lets us ensure that the password being used matches the defcon section password
         */
        if (found == true) {
            temp << CITADEL_VAULT_SIG_START << signature << CITADEL_VAULT_SIG_END << std::endl;
            found = false;
            continue;
        }
        temp << line << std::endl;
    }


    vault.close();
    temp.close();

    std::filesystem::remove(config.vault_file_path);
    std::filesystem::rename(temp_path, config.vault_file_path);
}

std::vector<std::string> read_all_entries(ConfigRepresentation &config,
                                          std::string *signature) {
    std::ifstream vault(config.vault_file_path);

    if (!vault.is_open()) {
        std::cerr << "Could not open fault file : " << config.vault_file_path << std::endl;
        exit(1);
    }

    if (std::filesystem::file_size(config.vault_file_path) > MAXIMUM_VAULT_SIZE) {
        std::cerr << std::filesystem::file_size(config.vault_file_path) <<
                " is too large for Citadel to handle. Please investigate." << std::endl;
        exit(1);
    }
    std::vector<std::string> values;
    std::string line;
    std::string sig;
    Defcon defcon;
    Defcon target_defcon = config.defcon;
    //found is used so that we dont jump to another defcon when weve grabbed keys from a different one. Read many is ONLY for entries in the same defcon level.
    bool in_defcon = false;

    while (std::getline(vault, line)) {
        if (line == CITADEL_DEFCON_1) {
            if (in_defcon == true) {
                return std::move(values);
            }

            defcon = Defcon::DEFCON1;

            if (defcon == target_defcon) {
                in_defcon = true;
            }

            continue;
        }

        if (line == CITADEL_DEFCON_2) {
            if (in_defcon == true) {
                return std::move(values);
            }

            defcon = Defcon::DEFCON2;

            if (defcon == target_defcon) {
                in_defcon = true;
            }


            continue;
        }

        if (line == CITADEL_DEFCON_3) {
            if (in_defcon == true) {
                return std::move(values);
            }

            defcon = Defcon::DEFCON3;

            if (defcon == target_defcon) {
                in_defcon = true;
            }

            continue;
        }
        if (line == CITADEL_DEFCON_4) {
            if (in_defcon == true) {
                return std::move(values);
            }

            defcon = Defcon::DEFCON4;

            if (defcon == target_defcon) {
                in_defcon = true;
            }

            continue;
        }
        if (line == CITADEL_DEFCON_5) {
            if (in_defcon == true) {
                return std::move(values);
            }
            defcon = Defcon::DEFCON5;
            continue;
        }

        if (line.starts_with(CITADEL_VAULT_SIG_START) && in_defcon == true) {
            logger.log(LogLevel::DEBUG, "read_entry()",
                       std::format("Signature for Defcon{} is {}", static_cast<int>(defcon), *line.c_str()));
            sig = line.replace(line.find(CITADEL_VAULT_SIG_START), strlen(CITADEL_VAULT_SIG_START) - 1, "").replace(
                line.find(CITADEL_VAULT_SIG_END), strlen(CITADEL_VAULT_SIG_END), "");
            continue;
        }

        if (line.starts_with('#')) // support comments
            continue;

        if (in_defcon == true) {
            std::string k = line.substr(0, line.find('='));
            std::string v = line.substr(line.find('=') + 1, line.size() - line.find('=') - 1);

            logger.log(LogLevel::DEBUG, "read_many_entries()", k);
            logger.log(LogLevel::DEBUG, "read_many_entries()", v);
            values.push_back(line);
            //Should we return the line for another function to be able to print the key or just pass values back? Probably best to pass the whole line and let another function parse the lines
            *signature = std::move(sig);
        }
    }

    exit(1);
}

/*
 *  Finds an entry and reads it into value.
 */

std::vector<std::string> read_many_entries(std::vector<std::string> &keys, ConfigRepresentation &config,
                                           std::string *signature) {
    std::ifstream vault(config.vault_file_path);

    if (!vault.is_open()) {
        std::cerr << "Could not open fault file : " << config.vault_file_path << std::endl;
        exit(1);
    }

    if (std::filesystem::file_size(config.vault_file_path) > MAXIMUM_VAULT_SIZE) {
        std::cerr << std::filesystem::file_size(config.vault_file_path) <<
                " is too large for Citadel to handle. Please investigate." << std::endl;
        exit(1);
    }
    std::vector<std::string> values;
    std::string line;
    std::string sig;
    Defcon defcon;
    //found is used so that we dont jump to another defcon when weve grabbed keys from a different one. Read many is ONLY for entries in the same defcon level.
    bool found = false;

    for (const auto &key: keys) {
        while (std::getline(vault, line)) {
            if (line == CITADEL_DEFCON_1) {
                if (found == true) {
                    return std::move(values);
                }
                defcon = Defcon::DEFCON1;
                continue;
            }

            if (line == CITADEL_DEFCON_2) {
                if (found == true) {
                    return std::move(values);
                }
                defcon = Defcon::DEFCON2;
                continue;
            }

            if (line == CITADEL_DEFCON_3) {
                if (found == true) {
                    return std::move(values);
                }
                defcon = Defcon::DEFCON3;
                continue;
            }
            if (line == CITADEL_DEFCON_4) {
                if (found == true) {
                    return std::move(values);
                }
                defcon = Defcon::DEFCON4;
                continue;
            }
            if (line == CITADEL_DEFCON_5) {
                if (found == true) {
                    return std::move(values);
                }
                defcon = Defcon::DEFCON5;
                continue;
            }

            if (line.starts_with(CITADEL_VAULT_SIG_START)) {
                logger.log(LogLevel::DEBUG, "read_entry()",
                           std::format("Signature for Defcon{} is {}", static_cast<int>(defcon), *line.c_str()));
                sig = line.replace(line.find(CITADEL_VAULT_SIG_START), strlen(CITADEL_VAULT_SIG_START) - 1, "").replace(
                    line.find(CITADEL_VAULT_SIG_END), strlen(CITADEL_VAULT_SIG_END), "");
                continue;
            }

            if (line.starts_with('#')) // support comments
                continue;

            std::string k = line.substr(0, line.find('='));
            std::string v = line.substr(line.find('=') + 1, line.size() - line.find('=') - 1);


            logger.log(LogLevel::DEBUG, "read_many_entries()", k);
            logger.log(LogLevel::DEBUG, "read_many_entries()", v);

            if (k == key) {
                found = true;
                values.push_back(v);
                *signature = std::move(sig);
            }
        }

        if (found == true) {
            return std::move(values);
        }
    }

    exit(1);
}

Defcon read_entry(std::string &key, std::string &value, ConfigRepresentation &config, std::string *signature) {
    std::ifstream vault(config.vault_file_path);

    if (!vault.is_open()) {
        std::cerr << "Could not open fault file : " << config.vault_file_path << std::endl;
        exit(1);
    }

    if (std::filesystem::file_size(config.vault_file_path) > MAXIMUM_VAULT_SIZE) {
        std::cerr << std::filesystem::file_size(config.vault_file_path) <<
                " is too large for Citadel to handle. Please investigate." << std::endl;
        exit(1);
    }

    std::string line;
    std::string sig;
    Defcon defcon;

    while (std::getline(vault, line)) {
        if (line == CITADEL_DEFCON_1) {
            defcon = Defcon::DEFCON1;
            continue;
        }

        if (line == CITADEL_DEFCON_2) {
            defcon = Defcon::DEFCON2;
            continue;
        }

        if (line == CITADEL_DEFCON_3) {
            defcon = Defcon::DEFCON3;
            continue;
        }
        if (line == CITADEL_DEFCON_4) {
            defcon = Defcon::DEFCON4;
            continue;
        }
        if (line == CITADEL_DEFCON_5) {
            defcon = Defcon::DEFCON5;
            continue;
        }

        if (line.starts_with(CITADEL_VAULT_SIG_START)) {
            logger.log(LogLevel::DEBUG, "read_entry()",
                       std::format("Signature for Defcon{} is {}", static_cast<int>(defcon), *line.c_str()));
            sig = line.replace(line.find(CITADEL_VAULT_SIG_START), strlen(CITADEL_VAULT_SIG_START) - 1, "").replace(
                line.find(CITADEL_VAULT_SIG_END), strlen(CITADEL_VAULT_SIG_END) - 1, "");
        }

        if (line.starts_with('#')) // support comments
            continue;

        std::string k = line.substr(0, line.find('='));
        std::string v = line.substr(line.find('=') + 1, line.size() - line.find('=') - 1);

        if (k == key) {
            value = std::move(v);
            *signature = std::move(sig);
            return defcon;
        }
    }

    std::cerr << "The key " << key << " is not present in the vault file." << std::endl;
    exit(1);
}


void list_all_entries(const ConfigRepresentation &config) {
    std::ifstream vault(config.vault_file_path);

    if (!vault.is_open()) {
        std::cerr << "Could not open fault file : " << config.vault_file_path << std::endl;
        exit(1);
    }

    if (std::filesystem::file_size(config.vault_file_path) > MAXIMUM_VAULT_SIZE) {
        std::cerr << std::filesystem::file_size(config.vault_file_path) <<
                " is too large for Citadel to handle. Please investigate." << std::endl;
        exit(1);
    }

    std::string line;

    while (std::getline(vault, line)) {
        if (line == CITADEL_DEFCON_1) {
            std::cout << CITADEL_DEFCON_1 << std::endl;
            continue;
        }

        if (line == CITADEL_DEFCON_2) {
            std::cout << CITADEL_DEFCON_2 << std::endl;
            continue;
        }

        if (line == CITADEL_DEFCON_3) {
            std::cout << CITADEL_DEFCON_3 << std::endl;
            continue;
        }
        if (line == CITADEL_DEFCON_4) {
            std::cout << CITADEL_DEFCON_4 << std::endl;
            continue;
        }
        if (line == CITADEL_DEFCON_5) {
            std::cout << CITADEL_DEFCON_5 << std::endl;
            continue;
        }

        if (line.starts_with(CITADEL_VAULT_SIG_START)) {
            continue;
        }

        if (line.starts_with('#')) // support comments
            continue;

        std::string k = line.substr(0, line.find('='));
        std::cout << k << std::endl;
    }

    exit(1);
}


void delete_entry(std::string &key, ConfigRepresentation &config) {
    std::ifstream vault(config.vault_file_path);
    if (!vault.is_open()) {
        std::cerr << "Could not open vault file: " << config.vault_file_path << std::endl;
        exit(1);
    }

    if (std::filesystem::file_size(config.vault_file_path) > MAXIMUM_VAULT_SIZE) {
        std::cerr << std::filesystem::file_size(config.vault_file_path)
                << " is too large for Citadel to handle. Please investigate." << std::endl;
        exit(1);
    }

    std::filesystem::path temp_path = config.vault_file_path;
    temp_path += ".tmp";
    std::ofstream temp(temp_path);
    if (!temp.is_open()) {
        std::cerr << "Could not create temp file" << std::endl;
        exit(1);
    }

    std::string line;
    bool found = false;

    while (std::getline(vault, line)) {
        if (line.starts_with('#')) {
            // support comments
            temp << line << std::endl;
            continue;
        }
        std::string k = line.substr(0, line.find('='));

        if (k == key) {
            found = true;
            continue;
        }

        temp << line << std::endl;
    }

    vault.close();
    temp.close();
    std::filesystem::rename(config.vault_file_path, config.vault_file_path.string() + ".old");
    // gives you one chance if you fuck up
    std::filesystem::rename(temp_path, config.vault_file_path);

    if (!found) {
        std::cerr << "Key not found: " << key << std::endl;
        exit(1);
    }

    std::cout << "Key: " << key << " removed from your vault. " <<
            "This deletion is recoverable until your next deletion and the backup is located at the same location as your vault ( "
            << config.
            vault_file_path << ") with a .old appended extension at the end of the filename." << std::endl;

    exit(0);
}

void rekey_defcon_level(Defcon defcon_level, ConfigRepresentation &config,
                        Encryption::EncryptionContext decryption_encryption_context,
                        Encryption::EncryptionContext new_key_encryption_context) {
    std::ifstream vault(config.vault_file_path);
    if (!vault.is_open()) {
        std::cerr << "Could not open vault file: " << config.vault_file_path << std::endl;
        exit(1);
    }

    if (std::filesystem::file_size(config.vault_file_path) > MAXIMUM_VAULT_SIZE) {
        std::cerr << std::filesystem::file_size(config.vault_file_path)
                << " is too large for Citadel to handle. Please investigate." << std::endl;
        exit(1);
    }

    std::filesystem::path temp_path = config.vault_file_path;
    temp_path += ".tmp";
    std::ofstream temp(temp_path);
    if (!temp.is_open()) {
        std::cerr << "Could not create temp file" << std::endl;
        exit(1);
    }

    decryption_encryption_context.current_defcon = defcon_level;
    new_key_encryption_context.current_defcon = defcon_level;

    std::cout << "Prepare to enter your OLD password for the section of the vault you are wish to re-key (DEFCON" <<
            static_cast<int>(defcon_level) << ")." << std::endl;

    decryption_encryption_context.receive_passphrase();

    auto ret = decryption_encryption_context.verify_defcon_signature(std::nullopt);

    if (!ret) {
        std::cerr << "Could not verify defcon signature with old password you provided." << std::endl;
        exit(1);
    }

    std::cout << "Prepare to enter your NEW password for the section of the vault you are wishing to re-key (DEFCON" <<
            static_cast<int>(defcon_level) << ")." << std::endl;

    std::string new_sig = new_key_encryption_context.generate_signature();

    std::string line;
    bool in_defcon = false;
    std::string current_defcon_string = defcon_level_to_string(defcon_level);

    while (std::getline(vault, line)) {
        if (line.starts_with('#')) {
            // support comments
            temp << line << std::endl;
            continue;
        }

        if (line.contains("<DEFCON") && in_defcon) {
            //we are entering a new defcon and thus no longer in the target defcon area
            in_defcon = false;
            temp << line << std::endl;
            continue;
        }
        if (line.contains(current_defcon_string)) {
            in_defcon = true;
            temp << line << std::endl;
            continue;
        }

        if (line.starts_with(CITADEL_VAULT_SIG_START) && in_defcon) {
            temp << CITADEL_VAULT_SIG_START << new_sig << CITADEL_VAULT_SIG_END << std::endl;
            continue;
        }

        if (in_defcon) {
            std::string k = line.substr(0, line.find('='));

            std::string v = line.substr(line.find('=') + 1, line.length());

            decryption_encryption_context.decrypt_string(v);

            new_key_encryption_context.secret = std::move(decryption_encryption_context.secret);

            auto new_value = new_key_encryption_context.encrypt_string();
            temp << k << "=" << new_value << std::endl;
            continue;
        }


        temp << line << std::endl;
    }

    vault.close();
    temp.close();
    std::filesystem::rename(config.vault_file_path, config.vault_file_path.string() + ".old");
    // gives you one chance if you fuck up
    std::filesystem::rename(temp_path, config.vault_file_path);

    exit(0);
}

void create_vault(std::filesystem::path &vault_path) {
    logger.log(LogLevel::DEBUG, "create_vault()", vault_path);
    if (std::filesystem::exists(vault_path)) {
        std::cerr << vault_path << " already exists!" << std::endl;
        exit(1);
    }
    std::filesystem::create_directories(vault_path.parent_path());
    std::ofstream vault(vault_path);
    if (!vault.is_open()) {
        std::cerr << "Could not open vault file: " << vault_path << std::endl;
        exit(1);
    }

    vault << "#Citadel vault file" << std::endl;
    vault <<
            "#This is an automatically generated and managed file. If you do NOT know what you are doing, do NOT touch ANYTHING here manually"
            << std::endl;
    vault << CITADEL_DEFCON_1 << std::endl;
    vault << CITADEL_DEFCON_2 << std::endl;
    vault << CITADEL_DEFCON_3 << std::endl;
    vault << CITADEL_DEFCON_4 << std::endl;
    vault << CITADEL_DEFCON_5 << std::endl;
    vault.close();
}

void handle_value_list(std::vector<std::string> values, Encryption::EncryptionContext &encryption_context) {
    encryption_context.receive_passphrase();

    for (const auto &value: values) {
        std::string k = value.substr(0, value.find('='));
        std::string v = value.substr(value.find('=') + 1, value.size() - value.find('=') - 1);

        encryption_context.decrypt_string(v);

        std::string plaintext = std::move(encryption_context.secret);

        std::cout << k << "=" << plaintext << std::endl;
    }

    exit(0);
}
