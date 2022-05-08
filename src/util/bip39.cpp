// Copyright (c) 2017-2020 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/hmac_sha512.h>
#include <random.h>
#include <util/bip39.h>

namespace {

// golang.org/x/crypto/pbkdf2/pbkdf2.go:
//
// Key derives a key from the password, salt and iteration count, returning a
// []byte of length keylen that can be used as cryptographic key. The key is
// derived based on the method described as PBKDF2 with the HMAC variant using
// the supplied hash function.
//
// For example, to use a HMAC-SHA-1 based PBKDF2 key derivation function, you
// can get a derived key for e.g. AES-256 (which needs a 32-byte key) by
// doing:
//
// 	dk := pbkdf2.Key([]byte("some password"), salt, 4096, 32, sha1.New)
//
// Remember to get a good random salt. At least 8 bytes is recommended by the
// RFC.
//
// Using a higher iteration count will increase the cost of an exhaustive
// search but will also make derivation proportionally slower.
template <typename CHasher>
std::vector<unsigned char> pbkdf2_key(const std::string& password, const std::string& salt, int iter, int key_len)
{
    const size_t hash_len = CHasher::OUTPUT_SIZE;
    const size_t num_blocks = ((size_t) key_len + hash_len - 1) / hash_len;

    std::vector<unsigned char> seed;
    seed.reserve(num_blocks * hash_len);

    std::vector<unsigned char> u(hash_len);
    for (size_t block = 1; block <= num_blocks; block++) {
        // N.B.: || means concatenation, ^ means XOR
        // for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
        // U_1 = PRF(password, salt || uint(i))
        {
            unsigned char blocks[4];
            blocks[0] = (unsigned char) (block >> 24);
            blocks[1] = (unsigned char) (block >> 16);
            blocks[2] = (unsigned char) (block >> 8);
            blocks[3] = (unsigned char) (block);

            CHasher prf((const unsigned char *) password.data(), password.size());
            prf.Write((const unsigned char *) salt.data(), salt.size());
            prf.Write(blocks, sizeof(blocks));
            prf.Finalize(u.data());
        }
        seed.insert(seed.end(), u.begin(), u.end());
        auto t = seed.end() - u.size();

        // U_n = PRF(password, U_(n-1))
        for (int n = 2; n <= iter; n++) {
            CHasher prf((const unsigned char *) password.data(), password.size());
            prf.Write(u.data(), u.size());
            prf.Finalize(u.data());
            for (size_t i = 0; i < u.size(); i++) {
                *(t+i) ^= u[i];
            }
        }
    }

    seed.resize(key_len);
    return seed;
}

}

std::vector<unsigned char> BIP39_MnemonicToSeed(const std::string& mnemonic, const std::string& password)
{
    const std::string salt = "mnemonic" + password;
    return pbkdf2_key<CHMAC_SHA512>(mnemonic, salt, 2048, CHMAC_SHA512::OUTPUT_SIZE);
}


CBIP39WordList BIP39_GenMnemonic(int words)
{
    assert (words % 4 == 0 && words >= 12 && words <= 32);

    uint32_t salt[32] = { 0 };
    for (size_t i = 0; i < sizeof(salt); i += 32) {
        GetStrongRandBytes((unsigned char* )&salt[0] + i, 32);
    }

    size_t pos = 0;
    CBIP39WordList wordlist(words);
    for (auto it = wordlist.begin(); it != wordlist.end(); it++) {
        size_t word_index = salt[pos++] % bip39_wordlist_english.size();
        *it = bip39_wordlist_english[word_index];
    }
    return wordlist;
}

CBIP39String BIP39_JoinMnemonic(const CBIP39WordList& wordlist)
{
    CBIP39String str;
    str.reserve(1024);
    for (auto it = wordlist.cbegin(); it != wordlist.cend(); it++) {
        if (!str.empty())
            str += " ";
        str += *it;
    }

    return str;
}