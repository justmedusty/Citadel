//
// Created by dustyn on 6/28/26.
//
#define BOOST_TEST_MODULE VaultOperationsTest
#include <boost/test/unit_test.hpp>
#include "filesystem/vault_handling.h"
#include "crypt/encryption.h"
#include "crypt/base64.h"
#include "config/config_representation.h"

BOOST_AUTO_TEST_CASE(arg_parsing_check_with_vault_creation) {
    std::filesystem::path vault_file_path = "/tmp/vault";
    std::filesystem::remove(vault_file_path); //if tests fail it can leave the dead files there so we must do this
    create_vault(vault_file_path);
    ConfigRepresentation config_representation(vault_file_path);
    const std::vector<std::string> args = {
        FLAG_ENCRYPT,
        FLAG_KEY,
        "my_secret",
        FLAG_DEFCON_LEVEL_TO_ENCRYPT,
        "1",
    };

    config_representation.parse_command_line_args(args);


    BOOST_CHECK_EQUAL(config_representation.vault_file_path, "/tmp/vault");
    BOOST_CHECK_EQUAL(config_representation.decrypt, false);
    BOOST_CHECK_EQUAL(config_representation.key, "my_secret");

    std::filesystem::remove(vault_file_path);
}

BOOST_AUTO_TEST_CASE(arg_parsing_check2_with_vault_creation) {
    std::filesystem::path vault_file_path = "/tmp/vault";
    std::filesystem::remove(vault_file_path); //if tests fail it can leave the dead files there so we must do this
    create_vault(vault_file_path);
    ConfigRepresentation config_representation(vault_file_path);
    const std::vector<std::string> args = {
        FLAG_DECRYPT,
        FLAG_KEY,
        "this_secret",
    };

    config_representation.parse_command_line_args(args);


    BOOST_CHECK_EQUAL(config_representation.vault_file_path, "/tmp/vault");
    BOOST_CHECK_EQUAL(config_representation.decrypt, true);
    BOOST_CHECK_EQUAL(config_representation.key, "this_secret");

    std::filesystem::remove(vault_file_path);
}

/*
 * NOTE FOR TESTING
 * DEFCON1 TAKES A FUCKING INSANELY LONG TIME TO DERIVE KEYS
 * FOR TESTING IT IS GENERALLY EASIER TO USE DEFCON5
 */
BOOST_AUTO_TEST_CASE(testing_top_level_encrypt_function) {
    std::filesystem::path vault_file_path = "/tmp/vault";
    std::filesystem::remove(vault_file_path); //if tests fail it can leave the dead files there so we must do this
    create_vault(vault_file_path);
    ConfigRepresentation config_representation(vault_file_path);
    const std::vector<std::string> args = {
        FLAG_ENCRYPT,
        FLAG_KEY,
        "my_secret",
        FLAG_DEFCON_LEVEL_TO_ENCRYPT,
        "5",
    };

    config_representation.parse_command_line_args(args);
    Encryption::EncryptionContext encryption_context(config_representation);
    encryption_context.passphrase = "supersecretpassword123!";
    encryption_context.secret = "test_secret123";
    std::string base64_ciphertext = encryption_context.encrypt_string();
    std::string base64_ciphertext2 = encryption_context.encrypt_string();

    std::cout << base64_ciphertext << std::endl;
    std::cout << base64_ciphertext2 << std::endl;

    BOOST_CHECK(!base64_ciphertext.empty());
    BOOST_CHECK_NE(base64_ciphertext, base64_ciphertext2);
    // These two are expected to differ because encrypt_string generates an IV and KDF salt

    std::filesystem::remove(vault_file_path);
}

BOOST_AUTO_TEST_CASE(testing_top_level_decrypt_function) {
    std::filesystem::path vault_file_path = "/tmp/vault";
    std::filesystem::remove(vault_file_path); //if tests fail it can leave the dead files there so we must do this
    create_vault(vault_file_path);
    ConfigRepresentation config_representation(vault_file_path);
    const std::vector<std::string> args = {
        FLAG_ENCRYPT,
        FLAG_KEY,
        "my_secret",
        FLAG_DEFCON_LEVEL_TO_ENCRYPT,
        "5",
    };

    config_representation.parse_command_line_args(args);
    Encryption::EncryptionContext encryption_context(config_representation);
    encryption_context.passphrase = "supersecretpassword123!";
    std::string base64_ciphertext = encryption_context.encrypt_string();
    std::cout << base64_ciphertext << std::endl;
    std::cout << "after enc" << std::endl;
    encryption_context.decrypt_string(base64_ciphertext);
    std::cout << encryption_context.secret << std::endl;
    BOOST_CHECK_EQUAL("test_secret123", encryption_context.secret);

    std::filesystem::remove(vault_file_path);
}

BOOST_AUTO_TEST_CASE(testing_top_level_decrypt_many_function) {
    std::filesystem::path vault_file_path = "/tmp/vault";
    std::filesystem::remove(vault_file_path); //if tests fail it can leave the dead files there so we must do this
    create_vault(vault_file_path);
    ConfigRepresentation config_representation(vault_file_path);
    const std::vector<std::string> args = {
        FLAG_ENCRYPT,
        FLAG_KEY,
        "my_secret",
        FLAG_DEFCON_LEVEL_TO_ENCRYPT,
        "5",
    };

    config_representation.parse_command_line_args(args);
    Encryption::EncryptionContext encryption_context(config_representation);
    encryption_context.passphrase = "supersecretpassword123!";

    /*
     * These all have their own tags and IV and KDF salts so we must be able to decrypt them all back to our inital test_secret string
     */
    std::string base64_ciphertext = encryption_context.encrypt_string();
    std::string base64_ciphertext2 = encryption_context.encrypt_string();
    std::string base64_ciphertext3 = encryption_context.encrypt_string();
    std::string base64_ciphertext4 = encryption_context.encrypt_string();


    std::cout << "after enc" << std::endl;

    encryption_context.decrypt_string(base64_ciphertext);
    BOOST_CHECK_EQUAL("test_secret123", encryption_context.secret);

    encryption_context.decrypt_string(base64_ciphertext2);
    BOOST_CHECK_EQUAL("test_secret123", encryption_context.secret);

    encryption_context.decrypt_string(base64_ciphertext3);
    BOOST_CHECK_EQUAL("test_secret123", encryption_context.secret);

    encryption_context.decrypt_string(base64_ciphertext4);
    BOOST_CHECK_EQUAL("test_secret123", encryption_context.secret);

    std::filesystem::remove(vault_file_path);
}

BOOST_AUTO_TEST_CASE(write_signature_test) {
    std::filesystem::path vault_file_path = "/tmp/vault";
    std::filesystem::remove(vault_file_path); //if tests fail it can leave the dead files there so we must do this
    create_vault(vault_file_path);
    ConfigRepresentation config_representation(vault_file_path);
    const std::vector<std::string> args = {
        FLAG_ENCRYPT,
        FLAG_KEY,
        "my_secret",
        FLAG_DEFCON_LEVEL_TO_ENCRYPT,
        "5",
    };


    config_representation.parse_command_line_args(args);
    Encryption::EncryptionContext encryption_context(config_representation);

    encryption_context.passphrase = "supersecretpassword123!";
    encryption_context.confirm_passphrase = "supersecretpassword123!";

    std::string sig = encryption_context.generate_signature();

    BOOST_CHECK(!sig.empty());
    std::cout << sig << std::endl;
    write_signature(sig, encryption_context.current_defcon, config_representation);
    std::cout << "wrote sig" << std::endl;
    BOOST_CHECK(encryption_context.verify_defcon_signature(sig));

    std::filesystem::remove(vault_file_path);
}

BOOST_AUTO_TEST_CASE(write_vault_test) {
    std::filesystem::path vault_file_path = "/tmp/vault";
    std::filesystem::path vault_file_path2 = "/tmp/vault";
    std::filesystem::remove(vault_file_path); //if tests fail it can leave the dead files there so we must do this
    create_vault(vault_file_path);
    ConfigRepresentation config_representation(vault_file_path);

    const std::vector<std::string> args = {
        FLAG_ENCRYPT,
        FLAG_KEY,
        "my_secret",
        FLAG_DEFCON_LEVEL_TO_ENCRYPT,
        "5",
    };


    config_representation.parse_command_line_args(args);
    Encryption::EncryptionContext encryption_context(config_representation);

    encryption_context.passphrase = "supersecretpassword123!";
    encryption_context.confirm_passphrase = "supersecretpassword123!";

    std::string sig = encryption_context.generate_signature();
    std::cout << sig << std::endl;
    write_signature(sig, encryption_context.current_defcon, config_representation);
    encryption_context.secret = "test_secret123";

    std::string encrypted_entry = encryption_context.encrypt_string();
    // encrypt the "test_secret123" string so we can insert it into the vault

    write_entry(config_representation.key, encrypted_entry, config_representation);


    std::string signature(100, '\0');
    std::string entry(100, '\0');

    auto ret = read_entry(config_representation.key, entry, config_representation, &signature);

    const std::vector<std::string> args2 = {
        FLAG_DECRYPT,
        FLAG_KEY,
        "my_secret",
    };

    //because the program will not have the same object handle two arg parsings (the program ends after the args are aprsed and the operation is done
    //i wont bother doing that in the test, if it doesnt work, thats fine because it doesnt need to
    ConfigRepresentation config_representation2(vault_file_path2);
    config_representation2.parse_command_line_args(args2);
    Encryption::EncryptionContext encryption_context2(config_representation2);

    encryption_context2.passphrase = "supersecretpassword123!";
    encryption_context2.current_defcon = Defcon::DEFCON5;

    auto def = read_entry(config_representation2.key, entry, config_representation2, &signature);
    encryption_context2.decrypt_string(entry);

    std::cout << encryption_context2.secret << std::endl;
    signature.resize(signature.length());
    BOOST_CHECK(signature.contains(sig));
    BOOST_CHECK_EQUAL(encryption_context2.secret, "test_secret123");
    BOOST_CHECK(ret == Defcon::DEFCON5);


    std::filesystem::remove(vault_file_path);
}

BOOST_AUTO_TEST_CASE(write_vault_test_many) {
    std::filesystem::path vault_file_path = "/tmp/vault";
    std::filesystem::path vault_file_path2 = "/tmp/vault";
    std::filesystem::remove(vault_file_path); //if tests fail it can leave the dead files there so we must do this
    create_vault(vault_file_path);
    ConfigRepresentation config_representation(vault_file_path);

    const std::vector<std::string> args = {
        FLAG_ENCRYPT,
        FLAG_KEY,
        "my_secret",
        FLAG_DEFCON_LEVEL_TO_ENCRYPT,
        "5",
    };


    config_representation.parse_command_line_args(args);
    Encryption::EncryptionContext encryption_context(config_representation);

    encryption_context.passphrase = "supersecretpassword123!";
    encryption_context.confirm_passphrase = "supersecretpassword123!";

    std::string sig = encryption_context.generate_signature();
    std::cout << sig << std::endl;
    write_signature(sig, encryption_context.current_defcon, config_representation);
    encryption_context.secret = "test_secret123";

    std::string encrypted_entry = encryption_context.encrypt_string();
    // encrypt the "test_secret123" string so we can insert it into the vault

    write_entry(config_representation.key, encrypted_entry, config_representation);


    std::string signature(100, '\0');
    std::string entry(100, '\0');

    auto ret = read_entry(config_representation.key, entry, config_representation, &signature);

    const std::vector<std::string> args2 = {
        FLAG_DECRYPT,
        FLAG_KEY,
        "my_secret",
    };

    //because the program will not have the same object handle two arg parsings (the program ends after the args are aprsed and the operation is done
    //i wont bother doing that in the test, if it doesnt work, thats fine because it doesnt need to
    ConfigRepresentation config_representation2(vault_file_path2);
    config_representation2.parse_command_line_args(args2);
    Encryption::EncryptionContext encryption_context2(config_representation2);

    encryption_context2.passphrase = "supersecretpassword123!";
    encryption_context2.current_defcon = Defcon::DEFCON5;

    auto def = read_entry(config_representation2.key, entry, config_representation2, &signature);
    encryption_context2.decrypt_string(entry);

    std::cout << encryption_context2.secret << std::endl;
    signature.resize(signature.length());
    BOOST_CHECK(signature.contains(sig));
    BOOST_CHECK_EQUAL(encryption_context2.secret, "test_secret123");
    BOOST_CHECK(ret == Defcon::DEFCON5);


    std::filesystem::remove(vault_file_path);
}

BOOST_AUTO_TEST_CASE(write_vault_test_different_levels) {
    std::filesystem::path vault_file_path = "/tmp/vault";
    std::filesystem::path vault_file_path2 = "/tmp/vault";
    std::filesystem::remove(vault_file_path); //if tests fail it can leave the dead files there so we must do this
    create_vault(vault_file_path);
    ConfigRepresentation config_representation(vault_file_path);

    const std::vector<std::string> args = {
        FLAG_ENCRYPT,
        FLAG_KEY,
        "my_secret",
        FLAG_DEFCON_LEVEL_TO_ENCRYPT,
        "5",
    };


    config_representation.parse_command_line_args(args);
    Encryption::EncryptionContext encryption_context(config_representation);

    encryption_context.passphrase = "supersecretpassword123!";
    encryption_context.confirm_passphrase = "supersecretpassword123!";

    std::string sig = encryption_context.generate_signature();
    std::cout << sig << std::endl;
    write_signature(sig, encryption_context.current_defcon, config_representation);
    encryption_context.secret = "test_secret123";

    std::string encrypted_entry = encryption_context.encrypt_string();
    // encrypt the "test_secret123" string so we can insert it into the vault

    write_entry(config_representation.key, encrypted_entry, config_representation);


    std::string signature(100, '\0');
    std::string entry(100, '\0');

    auto ret = read_entry(config_representation.key, entry, config_representation, &signature);

    const std::vector<std::string> args2 = {
        FLAG_DECRYPT,
        FLAG_KEY,
        "my_secret",
    };

    //because the program will not have the same object handle two arg parsings (the program ends after the args are aprsed and the operation is done
    //i wont bother doing that in the test, if it doesnt work, thats fine because it doesnt need to
    ConfigRepresentation config_representation2(vault_file_path2);
    config_representation2.parse_command_line_args(args2);
    Encryption::EncryptionContext encryption_context2(config_representation2);

    encryption_context2.passphrase = "supersecretpassword123!";
    encryption_context2.current_defcon = Defcon::DEFCON5;

    auto def = read_entry(config_representation2.key, entry, config_representation2, &signature);
    encryption_context2.decrypt_string(entry);

    std::cout << encryption_context2.secret << std::endl;
    signature.resize(signature.length());
    BOOST_CHECK(signature.contains(sig));
    BOOST_CHECK_EQUAL(encryption_context2.secret, "test_secret123");
    BOOST_CHECK(ret == Defcon::DEFCON5);


    std::filesystem::remove(vault_file_path);
}

/* This test is too destructive for use on a machine that you use this software on so it goes into the dungeon for now
BOOST_AUTO_TEST_CASE(check_home_directory) {
    ConfigRepresentation config_representation{};
    const std::vector<std::string> args = {
        FLAG_ENCRYPT,
        FLAG_KEY,
        "my_secret",
        FLAG_VALUE,
        "test_secret123",
        FLAG_DEFCON_LEVEL_TO_ENCRYPT,
        "5",
    };

    BOOST_CHECK(!config_representation.vault_file_path.empty());
    BOOST_CHECK(std::filesystem::exists(config_representation.vault_file_path));
    std::filesystem::remove(config_representation.vault_file_path);
    //if tests fail it can leave the dead files there so we must do this


    std::filesystem::remove(config_representation.vault_file_path);
}
*/
