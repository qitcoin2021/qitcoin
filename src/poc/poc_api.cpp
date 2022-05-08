// Copyright (c) 2017-2020 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <poc/poc.h>

#include <compat/endian.h>
#include <crypto/curve25519.h>
#include <crypto/sha256.h>
#include <crypto/shabal256.h>

namespace poc {

uint64_t GeneratePlotterId(const std::string &passphrase)
{
    // 1.passphraseHash = sha256(passphrase)
    // 2.<signingKey,publicKey> = Curve25519(passphraseHash)
    // 3.publicKeyHash = sha256(publicKey)
    // 4.unsigned int64 id = unsigned int64(publicKeyHash[0~7])
    uint8_t privateKey[32] = {0}, publicKey[32] = {0};
    CSHA256().Write((const unsigned char*)passphrase.data(), (size_t)passphrase.length()).Finalize(privateKey);
    crypto::curve25519_kengen(publicKey, nullptr, privateKey);
    return ToPlotterId(publicKey);
}

uint64_t ToPlotterId(const unsigned char publicKey[32])
{
    uint8_t publicKeyHash[32] = {0};
    CSHA256().Write((const unsigned char*)publicKey, 32).Finalize(publicKeyHash);
    return ((uint64_t)publicKeyHash[24]) | \
        ((uint64_t)publicKeyHash[25]) << 8 | \
        ((uint64_t)publicKeyHash[26]) << 16 | \
        ((uint64_t)publicKeyHash[27]) << 24 | \
        ((uint64_t)publicKeyHash[28]) << 32 | \
        ((uint64_t)publicKeyHash[29]) << 40 | \
        ((uint64_t)publicKeyHash[30]) << 48 | \
        ((uint64_t)publicKeyHash[31]) << 56;
}

bool Sign(const std::string &passphrase, const unsigned char data[32], unsigned char signature[64], unsigned char publicKey[32])
{
    uint8_t privateKey[32] = {0}, signingKey[32] = {0};
    CSHA256().Write((const unsigned char*)passphrase.data(), (size_t)passphrase.length()).Finalize(privateKey);
    crypto::curve25519_kengen(publicKey, signingKey, privateKey);

    unsigned char x[32], Y[32], h[32], v[32];
    CSHA256().Write(data, 32).Write(signingKey, 32).Finalize(x); // digest(m + s) => x
    crypto::curve25519_kengen(Y, NULL, x); // keygen(Y, NULL, x) => Y
    CSHA256().Write(data, 32).Write(Y, 32).Finalize(h); // digest(m + Y) => h
    int r = crypto::curve25519_sign(v, h, x, signingKey); // sign(v, h, x, s)
    if (r == 1) {
        memcpy(signature, v, 32);
        memcpy(signature + 32, h, 32);
        return true;
    } else
        return false;
}

bool Verify(const unsigned char publicKey[32], const unsigned char data[32], const unsigned char signature[64])
{
    unsigned char Y[32], h[32];
    crypto::curve25519_verify(Y, signature, signature + 32, publicKey); // verify25519(Y, signature, signature + 32, P) => Y
    CSHA256().Write(data, 32).Write(Y, 32).Finalize(h); // digest(m + Y) => h
    return memcmp(h, signature + 32, 32) == 0;
}

}
