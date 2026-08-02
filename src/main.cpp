#include <iostream>
#include <config/config_representation.h>
#include "crypt/encryption.h"
#include <optional>

int main(int argc, char **argv) {
#if defined(_WIN32)
    std::cout <<
            "You shouldn't use Windows. Just mentioning that in passing. Now let's get back to the vault activities." <<
            std::endl;
#endif
    logger.log(DEBUG, "main()", "attempting to lock memory...");
    Encryption::lock_memory();
    const std::vector<std::string> arguments(argv + 1, argv + argc);
    auto config = new ConfigRepresentation();
    config->parse_command_line_args(arguments);
    Encryption::EncryptionContext encryption_context(*config);
    auto ret = is_vault_setup(config->vault_file_path);

    if (!(ret & (1 << (static_cast<int>(config->defcon) - 1)))) {
        std::string sig = encryption_context.generate_signature();
        write_signature(sig, encryption_context.current_defcon, *config);
    }


    if (config->decrypt) {
        std::string signature(100, '\0'); // this is just an optional for verify defcon sig below
        std::string entry;
        auto def = read_entry(config->key, entry, *config, &signature);
        encryption_context.current_defcon = def;
        encryption_context.receive_passphrase();
        encryption_context.decrypt_string(entry);
        std::cout << encryption_context.secret << std::endl;
    } else {
        encryption_context.receive_passphrase();

        if (!encryption_context.verify_defcon_signature({})) {
            exit(1);
        }

        encryption_context.secret = std::move(config->value);
        auto encrypted_secret = encryption_context.encrypt_string();
        write_entry(config->key, encrypted_secret, *config);
    }

    return 0;
}
