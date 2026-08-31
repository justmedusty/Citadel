//
// Created by dustyn on 6/18/26.
//

#include "key_derivation.h"

#include <openssl/err.h>
#include <openssl/kdf.h>
#include <sys/sysinfo.h>

#include "algo/aes.h"
#include "config/config_representation.h"

//Platform agnostic get system memory, we are just doing this to ensure we arent going to absolutely shit their whole system down the
//drain with our tinfoil hate argon2 parameters.
uint64_t get_system_memory() {
#if defined(_WIN32)
    MEMORYSTATUSEX s;
    s.dwLength = sizeof(s);
    GlobalMemoryStatusEx(&s);
    return s.ullTotalPhys;

#elif defined(__APPLE__)
    uint64_t mem = 0;
    size_t len = sizeof(mem);
    sysctlbyname("hw.memsize", &mem, &len, nullptrptr, 0);
    return mem;

#elif defined(__FreeBSD__) || defined(__DragonFly__)
    uint64_t mem = 0;
    size_t len = sizeof(mem);
    sysctlbyname("hw.physmem", &mem, &len, nullptrptr, 0);
    return mem;

#elif defined(__NetBSD__) || defined(__OpenBSD__)
    uint64_t mem = 0;
    int mib[2] = {CTL_HW, HW_PHYSMEM64};
    size_t len = sizeof(mem);
    sysctl(mib, 2, &mem, &len, nullptrptr, 0);
    return mem;

#elif defined(__linux__)
    struct sysinfo info = {};
    sysinfo(&info);
    return (uint64_t) info.totalram * info.mem_unit;

#elif defined(_POSIX_VERSION)
    long p = sysconf(_SC_PHYS_PAGES);
    long ps = sysconf(_SC_PAGE_SIZE);
    return (p > 0 && ps > 0) ? (uint64_t) p * ps : 0;

#else
    std::cerr <<
            "I have no fucking idea what system you are running on. Cannot judge the memory size. This is needed to determine if it's safe to use our intended argon2 mem param (4GB)"
            << std::endl;
#endif
}

int derive_key(
    const std::string &password,
    std::vector<uint8_t> &salt,
    std::vector<std::byte> &key,
    Defcon defcon) // 32 bytes = AES-256
{
    auto keylen = AES_256_KEY_SIZE_BYTES;
    /*
     *  We will define the iters for the user, we will do something compute heavy to be as secure as possible while remaining within an
     *  interactive friendly timeframe.
     */

    uint64_t systemMemory = get_system_memory() / (1024 * 1024);


    uint64_t argon2MB = 2048;

    if(systemMemory < argon2MB){
        std::cout << "The amount of memory on your system (" << systemMemory << ") is not enough for the citadel memory requirements. If you must use this system, you should recompile and manually change argon2MB in key_derivation.cpp to be much lower and be aware that with this custom compiled binary you cannot use a different value for any secrets you encrypt with it." << std::endl;
        exit(1);
    }

    if((systemMemory - argon2MB) < (systemMemory / 2)){
        std::cout << "Your system memory will be very strained by the argon2 memory parameters, it should be able to pull it off, but be aware that there could be contention here.";
    }

    logger.log(LogLevel::DEBUG, "derive_key()",
               std::format("Amount of system memory available: {}MB , amount after checking min and max {}MB",
                           systemMemory,
                           argon2MB));


    int defcon_boost = 0; //How many rounds to boost from base rounds
    int memory_divisor = 1; //The defcon level will change the memory and rounds

    switch (defcon) {
        case Defcon::DEFCON1:
            defcon_boost = 24; //VERY high rounds boost, very good defense against CPU centric attacks
            memory_divisor = 1; // max memory usage, divide by 1 , fantastic defense against GPU centric attacks
            break;
        case Defcon::DEFCON2:
            defcon_boost = 12;
            memory_divisor = 2;
            break;
        case Defcon::DEFCON3:
            defcon_boost = 6;
            memory_divisor = 4;
            break;
        case Defcon::DEFCON4:
            defcon_boost = 3;
            memory_divisor = 6;
            break;
        case Defcon::DEFCON5:
            defcon_boost = 1; //Only +1 rounds boost, still high, but much much lower than DEFCON1
            memory_divisor = 12;
            //Memory divided by 12, absolute max of 1GB on a machine with a lot of memory, minimum of 85MB.
            break;
    }
    uint32_t m_cost = static_cast<uint32_t>((argon2MB * 1024) / memory_divisor); // Argon2 takes KB for the m_cost param

    uint32_t iterations = ARGON2_ROUNDS_BASE + defcon_boost;
    logger.log(LogLevel::DEBUG, "derive_key()",
               std::format("Your argon2 memory cost is {} and your iterations count is {}", m_cost, iterations));

    uint32_t parallelism = std::thread::hardware_concurrency(); // num lanes will be the number of cores on the system

    logger.log(LogLevel::DEBUG, "derive_key()",
               std::format("Reported cpucount is {}", parallelism));

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string("pass", const_cast<char *>(password.data()), password.size()),
        OSSL_PARAM_construct_octet_string("salt", (salt.data()), salt.size()),
        OSSL_PARAM_construct_uint32("memcost", &m_cost), // KB of RAM
        OSSL_PARAM_construct_uint32("iter", &iterations), // iterations
        OSSL_PARAM_construct_uint32("lanes", &parallelism), // parallel threads
        OSSL_PARAM_END
    };

    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (!kdf) {
        logger.log(LogLevel::ERROR, "derive_key()", "EVP_KDF_fetch failed");
        exit(1);
    }

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) {
        logger.log(LogLevel::ERROR, "derive_key()", "EVP_KDF_CTX_new failed");
        exit(1);
    }

    if (int ret; (ret = EVP_KDF_derive(ctx, reinterpret_cast<unsigned char *>(key.data()), keylen, params)) != 1) {
        logger.log(LogLevel::ERROR, "derive_key()",
                   std::format("EVP_KDF_derive failed: {}", *ERR_error_string(ERR_get_error(), nullptr)));

        EVP_KDF_CTX_free(ctx);
        exit(1);
    }

    EVP_KDF_CTX_free(ctx);
    return 1;
}

//generate a random salt (do this once, store alongside ciphertext)
void generate_salt(std::vector<uint8_t> &salt_buf) {
    logger.log(LogLevel::DEBUG, "generate_salt()", std::format("Generating salt of size {}", KDF_SALT_SIZE_BYTES));
    int len = KDF_SALT_SIZE_BYTES;
    salt_buf.resize(len);
    RAND_bytes(salt_buf.data(), len);
}




