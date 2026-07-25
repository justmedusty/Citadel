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
        logger.log(INFO, "is_vault_setup()",
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
    bool found = false;

    while (std::getline(vault, line)) {
        std::string k = line.substr(0, line.find('='));
        if (k == key) {
            std::cerr << k << " clashes with your new key : " << key << ". Aborting." << std::endl;
            exit(1);
        }
        temp << line << std::endl;
    }

    temp << key << '=' << value << std::endl;

    vault.close();
    temp.close();

    std::filesystem::remove(config.vault_file_path);
    std::filesystem::rename(temp_path, config.vault_file_path);
}

//An invariant of this function is that there is NOT an existing signature, this is a bug if this is ever called and a signature already exists.
void write_signature(std::string &signature, Defcon defcon, ConfigRepresentation &config) {
    std::string decfon_string;
    switch (defcon) {
        case Defcon::DEFCON1:
            decfon_string = CITADEL_DEFCON_1;
            break;
        case Defcon::DEFCON2:
            decfon_string = CITADEL_DEFCON_2;
            break;
        case Defcon::DEFCON3:
            decfon_string = CITADEL_DEFCON_3;
            break;
        case Defcon::DEFCON4:
            decfon_string = CITADEL_DEFCON_4;
            break;
        case Defcon::DEFCON5:
            decfon_string = CITADEL_DEFCON_5;
            break;
    }

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

/*
 *  Finds an entry and reads it into value.
 */

std::vector<std::string> read_many_entries(std::vector<std::string> keys, ConfigRepresentation &config,
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
    int num_found = 0;\
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
                logger.log(DEBUG, "read_entry()",
                           std::format("Signature for Defcon{} is {}", static_cast<int>(defcon), *line.c_str()));
                sig = line.replace(line.find(CITADEL_VAULT_SIG_START), strlen(CITADEL_VAULT_SIG_START) - 1, "").replace(
                    line.find(CITADEL_VAULT_SIG_END), strlen(CITADEL_VAULT_SIG_END) - 1, "");
            }

            if (line.starts_with('#')) // support comments
                continue;

            std::string k = line.substr(0, line.find('='));
            std::string v = line.substr(line.find('=') + 1, line.size() - line.find('=') - 1);


            logger.log(DEBUG, "read_many_entries()", k);
            logger.log(DEBUG, "read_many_entries()", v);

            if (k == key) {
                found = true;
                values.push_back(v);
                *signature = std::move(sig);
            }
        }

        if (found == true) {
            return std::move(values);
        }

        std::cerr << "The key " << key << " is not present in the vault file." << std::endl;
        exit(1);
    }
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
            logger.log(DEBUG, "read_entry()",
                       std::format("Signature for Defcon{} is {}", static_cast<int>(defcon), *line.c_str()));
            sig = line.replace(line.find(CITADEL_VAULT_SIG_START), strlen(CITADEL_VAULT_SIG_START) - 1, "").replace(
                line.find(CITADEL_VAULT_SIG_END), strlen(CITADEL_VAULT_SIG_END) - 1, "");
        }

        if (line.starts_with('#')) // support comments
            continue;

        std::string k = line.substr(0, line.find('='));
        std::string v = line.substr(line.find('=') + 1, line.size() - line.find('=') - 1);


        std::cout << k << ":" << v << std::endl;

        if (k == key) {
            value = v;
            *signature = std::move(sig);
            return defcon;
        }
    }

    std::cerr << "The key " << key << " is not present in the vault file." << std::endl;
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
    std::filesystem::rename(config.vault_file_path, config.vault_file_path.append(".old"));
    // gives you one chance if you fuck up
    std::filesystem::rename(temp_path, config.vault_file_path);

    if (!found) {
        std::cerr << "Key not found: " << key << std::endl;
        exit(1);
    }

    std::cout << "Key : " << key << "removed." <<
            "This deletion is recoverable until your next deletion and the backup is located at " << config.
            vault_file_path << ".old" << std::endl;
}

void create_vault(std::filesystem::path &vault_path) {
    logger.log(DEBUG, "create_vault()", vault_path);
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
