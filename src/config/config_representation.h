//
// Created by dustyn on 6/14/26.
//

#ifndef CITADEL_CONFIG_REPRESENTATION_H
#define CITADEL_CONFIG_REPRESENTATION_H
#include <filesystem>
#include <vector>
#include <iterator>
#include <iostream>
#include <openssl/crypto.h>
#include "log/log.h"
#include "filesystem/vault_handling.h"

enum class FileObfuscation;
enum class EncryptionMode;

#define ENCRYPTION_MODE_CONFIG_KEY "encryption_mode"
#define FILE_OBFUSCATION_CONFIG_KEY "filesystem_obfuscation"

#define STANDARD_VAULT_LOCATION ""

#define FLAG_HELP "-h"
#define FLAG_ENCRYPTION_ALGORITHM "-a"
#define FLAG_ENCRYPT "-e"
#define FLAG_DECRYPT "-d"
#define FLAG_KEY "-k"
#define FLAG_VALUE "-v"
#define FLAG_VAULT_FILE_LOCATION "-vf"
#define FLAG_DEFCON_LEVEL_TO_ENCRYPT "-defcon"
#define FLAG_LIST_ALL_KEYS "-ls"
#define FLAG_LOG_LEVEL "-loglevel"


#define FILE_NO_OBFUSCATION_CONFIG_KEY "no_obfuscation"
#define FILE_SCRAMBLING_CONFIG_KEY "file_scrambling"
#define FILE_EMBEDDED_CONFIG_KEY "embedded-in-another-file"
#define FILE_LOCATION_RANDOMIZATION_CONFIG_KEY "file-location-randomization"


#define ENCRYPTION_OPTION_AES_256_CBC_KEY "aes_256_cbc"
#define ENCRYPTION_OPTION_AES_256_GCM_KEY "aes_256_gcm"
#define ENCRYPTION_OPTION_BLOWFISH_THEN_AES_256_CBC "blowfish_then_aes_256_cbc"
#define ENCRYPTION_OPTION_CAMELLIA_THEN_AES_256_CBC "camelia_then_aes_256_cbc"
#define ENCRYPTION_OPTION_BLOWFISH_THEN_AES_256_GCM "blowfish_then_aes_256_gcm"
#define ENCRYPTION_OPTION_CAMELLIA_THEN_AES_256_GCM "camelia_then_aes_256_gcm"

/*
 *  Each section will have it's own password, this can let you pull more than 1 from a section in 1 operation.
 */
#define CITADEL_NUM_SECTIONS 5
#define CITADEL_DEFCON_1 "<DEFCON1>"
#define CITADEL_DEFCON_2 "<DEFCON2>"
#define CITADEL_DEFCON_3 "<DEFCON3>"
#define CITADEL_DEFCON_4 "<DEFCON4>"
#define CITADEL_DEFCON_5 "<DEFCON5>"

#define CITADEL_VAULT_SIG_START "<-- sig="
//The encrypted string to be placed under each defcon header to be a source of truth for the correctness of a password against a DEFCON level
#define CITADEL_ENCRYPTION_STRING "BECAUSE_I_CHOOSE_TO"
#define CITADEL_VAULT_SIG_END " -->"

enum class EncryptionMode {
    AES_256_GCM,
    /*
     *  I was going to support many algos but I might not.
     *  We will see.
     */
};


enum class Defcon {
    DEFCON1 = 1,
    DEFCON2 = 2,
    DEFCON3 = 3,
    DEFCON4 = 4,
    DEFCON5 = 5,
};


struct ConfigRepresentation {
    void parse_command_line_args(std::vector<std::string> args);


    explicit ConfigRepresentation(std::filesystem::path &vault) {
        vault_file_path = std::move(vault);
        decrypt = false;
        encryption_mode = EncryptionMode::AES_256_GCM;
    }

    explicit ConfigRepresentation() {
        vault_file_path = std::move(get_home_directory());

        if (!std::filesystem::exists(vault_file_path)) {
            logger.log(LogLevel::DEBUG, "create_vault()", "Creating vault in users home directory...");
            create_vault(vault_file_path);
        }

        decrypt = false;
        encryption_mode = EncryptionMode::AES_256_GCM;
    }


    ~ConfigRepresentation() {
        OPENSSL_cleanse(value.data(), value.size());
    }

    bool decrypt;
    std::string key;
    std::string value;
    EncryptionMode encryption_mode;
    std::filesystem::path vault_file_path;
    Defcon defcon;

private:
    static std::filesystem::path get_home_directory();

    static void help() {
        std::cout <<
                """This program is meant to be used as a key value vault for secure local password or other short strings."
                << std::endl <<
                "It is intended to be used with the following flags : " << std::endl <<
                "-e -> marks this operation as an ENCRYPT operation. This is default behavior. (requires a key and a value)"
                << std::endl <<
                "-d -> marks this operation a a DECRYPT operation, just requires a key and you will be prompted for your password to retrieve the value"
                << std::endl <<
                "-vf -> precedes a path string, points to a specific location for your vault file, main reason would be if your vault file is in a non-standard location such as a mounted flash drive"
                << std::endl <<
                "-k -> precedes the key to the value you are trying to retreive from the vault" << std::endl <<
                "-v -> precedes the value FOR ENCRYPTION OPERATION ONLY." << std::endl <<
                "-h -> display the help message you are currently reading." << std::endl <<
                "-dk -> delete a key and its associated value from the vault" << std::endl <<
                "-defcon -> precedes an integer (1,2,3,4,5) for an ENCRYPT operation only, specifies where the new entry should go"
                << std::endl <<
                "-ls -> lists all entries in your vault" << std::endl <<
                "-v -> verbosity/log level, precedes an acceptable values are debug, info, warn, error, critical. Default is error."
                << std::endl <<
                "-repass -> precedes a DEFCON option, DEFCON1 for defcon 1 and so on. Changes the password for that entire section of the vault. You must verify the current password first."
                << std::endl << std::endl <<
                "This program has 5 separate levels of the vault:" << std::endl <<
                "DEFCON1 -> MOST SERIOUS SECRETS, SHOULD HAVE FEW ENTRIES AND MAXIMALLY COMPLEX PASSWORD" << std::endl
                <<
                "DEFCON2 -> VERY SERIOUS SECRETS, SHOULD ALSO HAVE FEW ENTRIES AND A MAXIMALLY COMPLEX PASSWORD" <<
                std::endl <<
                "DEFCON3 -> MID-LEVEL SERIOUS SECRETS, SHOULD HAVE A COMPLEX PASSWORD, COULD BE WRITTEN DOWN ON PAPER"
                << std::endl <<
                "DEFCON4 -> LESS-SERIOUS, ONLINE ACCOUNT PASSWORDS AND THINGS OF THIS NATURE, COULD BE WRITTEN DOWN ON PAPER"
                << std::endl <<
                "DEFCON5 -> LEAST SERIOUS, PASSWORD DOES NOT NEED TO BE VERY COMPLEX JUST ENOUGH TO KEEP LOOKY LOOS OUT, COULD BE WRITTEN DOWN ON PAPER"
                ""
                << std::endl;
        exit(0);
    }
};


#endif //CITADEL_CONFIG_REPRESENTATION_H
