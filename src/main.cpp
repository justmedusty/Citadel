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

    if (!(ret & (1 << static_cast<int>(config->defcon)))) {
        std::string sig = encryption_context.generate_signature();
        write_signature(sig,encryption_context.current_defcon,*config);
    }
    encryption_context.receive_passphrase();

    if (config->decrypt) {
        std::optional<std::string> signature; // this is just an optional for verify defcon sig below
        read_entry(config->key,encryption_context.secret,*config,&signature.value());
        encryption_context.verify_defcon_signature(signature);
    }else {
        encryption_context.verify_defcon_signature({});
        write_entry(config->key,encryption_context.secret,*config);
    }



    return 0;
}
