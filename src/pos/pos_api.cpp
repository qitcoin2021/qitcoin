// Copyright (c) 2021-2022 The Qitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/pos.h>

#include <arith_uint256.h>
#include <crypto/sha256.h>
#include <poc/poc.h>
#include <primitives/block.h>
#include <util/bip39.h>
#include <util/strencodings.h>

namespace {

inline uint256 sha256(const std::vector<pos::Bytes>& data) {
    uint256 result;

    CSHA256 hash;
    for (auto it = data.begin(); it != data.end(); it++) {
        if (!it->empty())
            hash.Write(&(*it)[0], it->size());
    }
    hash.Finalize((unsigned char*)result.begin());

    return result;
}

bls::PrivateKey DerivePrivateKey(const bls::PrivateKey& privateKey, const std::vector<uint32_t>& path)
{
    bls::PrivateKey sk = privateKey;
    for (auto it = path.begin(); it != path.end(); it++)
        sk = bls::AugSchemeMPL().DeriveChildSk(sk, *it);
    return sk;
}

}

namespace pos {

bls::PrivateKey GeneratePrivateKey(const std::string& passphrase)
{
    auto seed = BIP39_MnemonicToSeed(passphrase, "");
    return bls::AugSchemeMPL().KeyGen(seed);
}

bls::PrivateKey DeriveMasterToFarmer(const bls::PrivateKey& privateKey)
{
    return DerivePrivateKey(privateKey, {12381, 8444, 0, 0});
}
bls::PrivateKey DeriveMasterToPool(const bls::PrivateKey& privateKey)
{
    return DerivePrivateKey(privateKey, {12381, 8444, 1, 0});
}
bls::PrivateKey DeriveMasterToLocal(const bls::PrivateKey& privateKey)
{
    return DerivePrivateKey(privateKey, {12381, 8444, 3, 0});
}

uint64_t ToFarmerId(const unsigned char farmerPublicKey[48])
{
    uint256 seed;
    CSHA256()
        .Write(farmerPublicKey, 48)
        .Finalize((unsigned char*)seed.begin());

    auto privateKey = bls::AugSchemeMPL().KeyGen(std::vector<uint8_t>(seed.begin(), seed.end()));
    return sha256({ privateKey.GetG1Element().Serialize() }).GetUint64(0);
}

uint64_t ToFarmerId(const std::vector<unsigned char> &farmerPubKey)
{
    if (farmerPubKey.size() != bls::G1Element::SIZE)
        return 0;

    return ToFarmerId(&farmerPubKey[0]);
}

uint256 CreatePlotId(const Bytes& poolPubKey, const Bytes& plotPubKey)
{
    return sha256({poolPubKey, plotPubKey});
}

uint256 CreatePlotId(const bls::G1Element& poolPubKey, const bls::G1Element& plotPubKey)
{
    return sha256({ poolPubKey.Serialize(), plotPubKey.Serialize() });
}

std::string ConvertPlotIdToString(const uint256& plotId)
{
    return HexStr(plotId);
}

bls::G1Element CreatePlotPubKey(const bls::G1Element& localPubKey, const bls::G1Element& farmerPubKey)
{
    return localPubKey + farmerPubKey;
}

bls::G1Element CreatePlotPubKey(const bls::G1Element& localPubKey, const bls::G1Element& farmerPubKey, bool includeTaproot)
{
    if (includeTaproot) {
        bls::PrivateKey taprootPrivateKey = CreateTaprootPrivateKey(localPubKey, farmerPubKey);
        return CreatePlotPubKey(localPubKey, farmerPubKey, taprootPrivateKey.GetG1Element());
    }

    return localPubKey + farmerPubKey;
}

bls::G1Element CreatePlotPubKey(const bls::G1Element& localPubKey, const bls::G1Element& farmerPubKey, const bls::G1Element& taprootPubKey)
{
    if (taprootPubKey.IsValid()) {
        return localPubKey + farmerPubKey + taprootPubKey;
    }

    return localPubKey + farmerPubKey;
}

bls::PrivateKey CreateTaprootPrivateKey(const bls::G1Element& localPubKey, const bls::G1Element& farmerPubKey)
{
    uint256 taprootHash = sha256({
        (localPubKey + farmerPubKey).Serialize(),
        localPubKey.Serialize(),
        farmerPubKey.Serialize(),
    });
    return bls::AugSchemeMPL().KeyGen(std::vector<unsigned char>(taprootHash.begin(), taprootHash.end()));
}

uint256 CreateChallenge(const uint256& challenge, int32_t scanIterations)
{
    uint64_t salt = htobe64(static_cast<uint64_t>(scanIterations));

    uint256 result;
    CSHA256()
        .Write(challenge.begin(), challenge.size())
        .Write((const unsigned char*)&salt, 8)
        .Finalize((unsigned char*)result.begin());
    return result;
}

std::pair<uint64_t, uint64_t> GenerateStakingPoolNonces(const uint256 &epochHash, uint32_t nTargetHeight, const CAccountID &poolID, uint64_t votePower)
{
    const uint32_t height_be = htobe32(nTargetHeight);
    uint64_t bestNonce = 0, bestDeadline = std::numeric_limits<uint64_t>::max();
    for (uint64_t nonce = 1; nonce <= votePower; nonce++) {
        const uint64_t nonce_be = htobe64(nonce);

        uint256 result;
        CSHA256().Write(epochHash.begin(), uint256::WIDTH).
                  Write(poolID.begin(), CAccountID::WIDTH).
                  Write((const unsigned char*)&height_be, sizeof(height_be)).
                  Write((const unsigned char*)&nonce_be, sizeof(nonce_be)).
                  Finalize((unsigned char*)&result);

        uint64_t deadline = result.GetUint64(0);
        if (deadline < bestDeadline) {
            bestNonce = nonce;
            bestDeadline = deadline;
        }
    }
    return std::make_pair(bestNonce, bestDeadline);
}

}
