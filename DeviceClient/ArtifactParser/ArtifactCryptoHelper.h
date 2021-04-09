
#ifndef UPDATECLIENT_ARTIFACTCRYPTOHELPER_H
#define UPDATECLIENT_ARTIFACTCRYPTOHELPER_H

#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <vector>
#include <fstream>
#include <cstring>
#include <cerrno>
#include <array>
#include <algorithm>
#include <openssl/rsa.h>

class verify_signature_exception : public std::runtime_error {
public:
    explicit verify_signature_exception(const char* message) : std::runtime_error(message) {}
};

class decryption_exception : public std::runtime_error {
public:
    explicit decryption_exception(const char* message) : std::runtime_error(message) {}
};

class ArtifactCryptoHelper {

private:
    static RSA* LoadPrivateKey(const std::string& path) {
        FILE* keyFile = fopen(path.c_str(), "rb");
        if (keyFile == nullptr) {
            std::cout << strerror(errno) << "\n";
            return nullptr;
        }
        RSA* key = nullptr;
        PEM_read_RSAPrivateKey(keyFile, &key, nullptr, nullptr);
        fclose(keyFile);
        return key;
    }

    static EVP_PKEY* LoadPublicKey(const std::string& path) {
        FILE* keyFile = fopen(path.c_str(), "rb");
        if (keyFile == nullptr) {
            std::cout << strerror(errno) << "\n";
            return nullptr;
        }
        EVP_PKEY* pkey = PEM_read_PUBKEY(keyFile, nullptr, nullptr, nullptr);
        fclose(keyFile);
        return pkey;
    }

    static void FreePublicKey(EVP_PKEY* key) {
        EVP_PKEY_free(key);
    }

    static void FreePrivateKey(RSA* key) {
        RSA_free(key);
    }

public:
    static std::array<unsigned char, 16> decryptAESKey(const std::string& privateKeyPath,
                                                       const std::array<unsigned char, 256>& ciphertext) {

        auto privateKey = LoadPrivateKey(privateKeyPath);
        if (privateKey == nullptr) {
            throw decryption_exception("failed to load key");
        }
        std::array<unsigned char, 16> plaintext;

        int numDecrypted = RSA_private_decrypt(256, ciphertext.data(), plaintext.data(), privateKey, RSA_PKCS1_PADDING);

        if (numDecrypted <= 0) {
            ERR_print_errors_fp(stderr);
            throw decryption_exception("decryption failed");
        }

        FreePrivateKey(privateKey);

        return plaintext;
    }

    static std::vector<unsigned char>
    AESGCMDecrypt(const std::vector<unsigned char>& ciphertext,
                  const std::array<unsigned char, 16>& key,
                  const std::array<unsigned char, 12>& iv) {

        EVP_CIPHER_CTX* ctx;

        if (!(ctx = EVP_CIPHER_CTX_new())) {
            ERR_print_errors_fp(stderr);
            throw decryption_exception("decryption failed");
        }

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
            ERR_print_errors_fp(stderr);
            throw decryption_exception("decryption failed");
        }

        if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
            ERR_print_errors_fp(stderr);
            throw decryption_exception("decryption failed");
        }

        int len;
        std::vector<unsigned char> plaintext(ciphertext.size() - 16, 0);

        if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size() - 16)) {
            ERR_print_errors_fp(stderr);
            throw decryption_exception("decryption failed");
        }

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                 (void*) (ciphertext.data() + ciphertext.size() - 16))) {
            ERR_print_errors_fp(stderr);
            throw decryption_exception("decryption failed");
        }

        int ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);

        EVP_CIPHER_CTX_free(ctx);
        if (!ok) {
            // Authentication-Tag can't be validated -> return empty plaintext
            plaintext.resize(0);
        }
        return plaintext;
    }

    static bool VerifyArtifactSignature(const std::string& keyPath, const std::vector<unsigned char>& msg) {

        auto pkey = ArtifactCryptoHelper::LoadPublicKey(keyPath);

        if (pkey == nullptr) {
            throw verify_signature_exception("failed to load key");
        }

        EVP_MD_CTX* mdctx;

        if (!(mdctx = EVP_MD_CTX_create())) {
            ERR_print_errors_fp(stderr);
            throw verify_signature_exception("signature verification failed");
        }

        if (1 != EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey)) {
            ERR_print_errors_fp(stderr);
            throw verify_signature_exception("signature verification failed");
        }

        if (1 != EVP_DigestVerifyUpdate(mdctx, msg.data() + 256, msg.size() - 256)) {
            ERR_print_errors_fp(stderr);
            throw verify_signature_exception("signature verification failed");
        }

        bool ok = EVP_DigestVerifyFinal(mdctx, msg.data(), 256);
        FreePublicKey(pkey);
        EVP_MD_CTX_free(mdctx);
        return ok;
    }
};

#endif //UPDATECLIENT_ARTIFACTCRYPTOHELPER_H
