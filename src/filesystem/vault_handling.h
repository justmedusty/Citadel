//
// Created by dustyn on 6/16/26.
//

#ifndef CITADEL_VAULT_HANDLING_H
#define CITADEL_VAULT_HANDLING_H

#include <filesystem>

#define MAXIMUM_VAULT_SIZE (1024 * 1024 * 1024) // This is arbitrary but because we are reading the entire file into memory we need a sanity check, 1MB is absolutely massive so this should never happen



enum class Defcon;
struct ConfigRepresentation;

bool is_vault_setup(std::filesystem::path &vault_file_path);

void write_entry(std::string &key, std::string &value, ConfigRepresentation &config);

void write_signature(std::string &signature, Defcon defcon, ConfigRepresentation &config);

Defcon read_entry(std::string &key, std::string &value, ConfigRepresentation &config, std::string *signature);

void delete_entry(std::string &key, ConfigRepresentation &config);

std::string get_defcon_signature(std::string &vault_file_path, Defcon defcon);

void create_vault(std::filesystem::path &vault_path);

#endif //CITADEL_VAULT_HANDLING_H
