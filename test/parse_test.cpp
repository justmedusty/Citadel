//
// Created by dustyn on 6/17/26.
//

#define BOOST_TEST_MODULE ParseTests
#include <boost/test/unit_test.hpp>
#include "filesystem/vault_handling.h"

BOOST_AUTO_TEST_CASE(can_create_vault_file) {
    std::filesystem::path vault_file_path = "/tmp/vault2";
    std::filesystem::remove(vault_file_path);
    create_vault(vault_file_path);
    BOOST_CHECK_EQUAL(vault_file_path.filename().string(), "vault2");
    std::filesystem::remove(vault_file_path);
}

BOOST_AUTO_TEST_CASE(created_vault_file_is_setup) {
    std::filesystem::path vault_file_path = "/tmp/vault2";
    std::filesystem::remove(vault_file_path);
    create_vault(vault_file_path);
    auto ret = is_vault_setup(vault_file_path);
    BOOST_CHECK(ret >= 0);
    std::filesystem::remove(vault_file_path);
}

