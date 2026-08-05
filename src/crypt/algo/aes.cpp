//
// Created by dustyn on 6/15/26.
//

#include "aes.h"
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string>
#include <iostream>

#include "log/log.h"

void handle_openssl_errors(std::string *where) {
    std::cout << "OpenSSL Error: " << where << std::endl;
    exit(1);
}


bool aes_256_gcm_encrypt(unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                         const unsigned char *iv, unsigned char *ciphertext, int *ciphertext_len, unsigned char *tag) {
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = nullptr;
    int tmplen = 0;
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_encrypt()", "EVP_CIPHER_CTX_new() returned a null pointer");
        goto err;
    }


    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr)) == nullptr) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_encrypt()", "EVP_CIPHER_fetch() for cipher AES 256 GCM returned a null pointer");
        goto err;
    }


    if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, params)) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_encrypt()", "EVP_EncryptInit_ex2() returned a null pointer");
        goto err;
    }


    /* Encrypt plaintext */
    if (!EVP_EncryptUpdate(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len)) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_encrypt()", "EVP_EncryptUpdate() failed during the encryption process");
        goto err;
    }

    /* Finalise: note get no output for GCM */
    if (!EVP_EncryptFinal_ex(ctx, ciphertext, &tmplen)) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_encrypt()", "EVP_EncryptFinal_ex() failed during the final call");
        goto err;
    }


    /* Get tag */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  tag, 16);

    if (!EVP_CIPHER_CTX_get_params(ctx, params)) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_encrypt()",
                   "EVP_CIPHER_CTX_get_params() failed while trying to get the GCM AEAD tag");
        goto err;
    }


    ret = 1;
err:
    if (!ret) {
        ERR_print_errors_fp(stderr);
    }


    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

bool aes_256_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
                         const unsigned char *iv, unsigned char *plaintext, int &plaintext_len,
                         unsigned char *tag) {
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = nullptr;
    bool tag_authenticated = false;
    int rv;

    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_decrypt()",
                   "EVP_CIPHER_CTX_new() returned a null pointer instead of a new context");
        goto err;
    }

    /* Fetch the cipher implementation */
    //nullptr for lib context and properties just resorts to default , we are fine with this
    if ((cipher = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr)) == nullptr) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_decrypt()",
                   "EVP_CIPHER_fetch() for algorithm AES 256 GCM returned a null pointer");
        goto err;
    }


    /*
     * Initialise an encrypt operation with the cipher/mode, key, IV and
     * IV length parameter.
     */
    if (!EVP_DecryptInit_ex2(ctx, cipher, key, iv, params)) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_decrypt()",
                   "EVP_DecryptInit_ex2() failed, initialization of decryption operation cannot proceed");
        goto err;
    }


    /* Decrypt plaintext */
    if (!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len)) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_decrypt()", "EVP_DecryptUpdate() failed during decryption process");
        goto err;
    }


    /* Set expected tag value. */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  (void *) tag, sizeof(tag));

    if (!EVP_CIPHER_CTX_set_params(ctx, params)) {
        logger.log(LogLevel::ERROR, "aes_256_gcm_decrypt()",
                   "EVP_CIPHER_CTX_set_params() failed while trying to set the expected AEAD tag value");
        goto err;
    }

    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, plaintext, &plaintext_len);

    tag_authenticated = rv > 0;
    if (tag_authenticated) {
        logger.log(LogLevel::INFO, "aes_256_gcm_decrypt()", "AES 256 GCM AEAD Tag is valid");
        ret = 1;
    } else {
        std::cerr << "The provided password is incorrect" << std::endl;
    }

err:
    if (!ret) {
        ERR_print_errors_fp(stderr);
    }


    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}
