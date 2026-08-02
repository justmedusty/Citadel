cmake_minimum_required(VERSION 4.2)
project(Citadel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS unit_test_framework)

add_library(CitadelCore
        src/config/config_representation.cpp
        src/crypt/encryption.cpp
        src/crypt/algo/aes.cpp
        src/filesystem/vault_handling.cpp
        src/crypt/base64.cpp
        src/crypt/key_derivation.cpp
        src/log/log.h
)

target_include_directories(CitadelCore PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(CitadelCore PUBLIC OpenSSL::Crypto)

add_executable(citadel
        src/main.cpp
)
target_link_libraries(citadel PRIVATE CitadelCore)

add_executable(CitadelParseTests
        test/parse_test.cpp
)
add_executable(CitadelEncryptionTests
        test/encryption_test.cpp
)

add_executable(CitadelKeyDerivationTests
        test/key_derivation_test.cpp
)

add_executable(CitadelVaultOperationsTests
        test/vault_operations_test.cpp
)

target_link_libraries(CitadelVaultOperationsTests PRIVATE
        CitadelCore
        Boost::unit_test_framework
)


target_link_libraries(CitadelKeyDerivationTests PRIVATE
        CitadelCore
        Boost::unit_test_framework
)

target_link_libraries(CitadelEncryptionTests PRIVATE
        CitadelCore
        Boost::unit_test_framework
)

target_link_libraries(CitadelParseTests  PRIVATE
        CitadelCore
        Boost::unit_test_framework
)

target_compile_options(CitadelCore PUBLIC -fsanitize=address -g)
target_link_options(CitadelCore PUBLIC -fsanitize=address)

enable_testing()
add_test(NAME CitadelParseTests COMMAND CitadelParseTests)
add_test(NAME CitadelEncryptionTests COMMAND CitadelEncryptionTests)
add_test(NAME CitadelKeyDerivationTests COMMAND CitadelKeyDerivationTests)
add_test(NAME CitadelVaultOperationsTests COMMAND CitadelVaultOperationsTests)