//
// Created by dustyn on 6/16/26.
//

#ifndef CITADEL_VAULT_HANDLING_H
#define CITADEL_VAULT_HANDLING_H

#include <filesystem>

#define MAXIMUM_VAULT_SIZE (1024 * 1024 * 1024) // This is arbitrary but because we are reading the entire file into memory we need a sanity check, 1MB is absolutely massive so this should never happen



#define DEFCON1_SIG_PRESENT (1 << 0)
#define DEFCON2_SIG_PRESENT (1 << 1)
#define DEFCON3_SIG_PRESENT (1 << 2)
#define DEFCON4_SIG_PRESENT (1 << 3)
#define DEFCON5_SIG_PRESENT (1 << 4)

namespace Encryption {
    struct EncryptionContext;
}

enum class Defcon;
struct ConfigRepresentation;

int8_t is_vault_setup(std::filesystem::path &vault_file_path);

void write_entry(std::string &key, std::string &value, ConfigRepresentation &config);

void write_signature(std::string &signature, Defcon defcon, ConfigRepresentation &config);

Defcon read_entry(std::string &key, std::string &value, ConfigRepresentation &config, std::string *signature);

void delete_entry(std::string &key, ConfigRepresentation &config);

std::string get_defcon_signature(std::string &vault_file_path, Defcon defcon);

void create_vault(std::filesystem::path &vault_path);

std::vector<std::string> read_many_entries(std::vector<std::string> &keys, ConfigRepresentation &config,
                                           std::string *signature);

void list_all_entries(const ConfigRepresentation &config);

void rekey_defcon_level(Defcon defcon_level, ConfigRepresentation &config,
                        Encryption::EncryptionContext decryption_encryption_context,
                        Encryption::EncryptionContext new_key_encryption_context);

void handle_value_list(std::vector<std::string> values, Encryption::EncryptionContext &encryption_context);

std::vector<std::string> read_all_entries(ConfigRepresentation &config,
                                          std::string *signature);
#endif //CITADEL_VAULT_HANDLING_H
