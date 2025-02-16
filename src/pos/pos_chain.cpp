// Copyright (c) 2021-2022 The Qitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/pos.h>

#include <chain.h>
#include <poc/poc.h>
#include <primitives/block.h>

#include <chiapos/api.h>

namespace {

inline uint256 sha256(const std::vector<uint256>& data) {
    uint256 result;

    CSHA256 hash;
    for (auto it = data.begin(); it != data.end(); it++) {
        hash.Write(it->begin(), it->size());
    }
    hash.Finalize((unsigned char*)result.begin());

    return result;
}

inline arith_uint1024 arith_uint1024_shift(unsigned int shift)
{
    arith_uint1024 value(1);
    return value << shift;
}

inline uint64_t expected_plot_size(int32_t k)
{
    return ((2ull * k) + 1) * (1ull << (k - 1));
}

bool passes_plot_filter(const uint256& plotId, const uint256& challenge, int filterBits)
{
    assert(filterBits >= 0 && filterBits < 32);
    if (filterBits == 0)
        return true;

    uint8_t hash[32];
    CSHA256()
        .Write(plotId.begin(), plotId.size())
        .Write(challenge.begin(), challenge.size())
        .Finalize(hash);

    // filter bits: Diff with chia's BitArray
    uint32_t data = ((uint32_t)hash[0]) | ((uint32_t)hash[1]) << 8 | ((uint32_t)hash[2]) << 16 | ((uint32_t)hash[3]) << 24;
    data = data << (32 - filterBits);
    return data == 0;
}

inline bool check_pos(const CChiaProofOfSpace& pos)
{
    if (pos.IsNull() || !pos.IsValid())
        return false;

    if (pos.nPlotK < pos::MIN_PLOT_SIZE || pos.nPlotK > pos::MAX_PLOT_SIZE)
        return false;

    return true;
}

::pos::VerifyResult VerifyAndGetIterations(
    uint64_t& iterations,
    const CBlockIndex& prevBlockIndex,
    const CChiaProofOfSpace& pos,
    const uint256& challenge,
    const Consensus::Params& params)
{
    // 1.create plot public key
    bls::G1Element plotPubKey = pos::CreatePlotPubKey(
        bls::G1Element::FromByteVector(pos.vchLocalPubKey),
        bls::G1Element::FromByteVector(pos.vchFarmerPubKey),
        pos.vchPoolPubKey.size() == 32);

    // 2.create and filter plot id
    const uint256 plotId = ::pos::CreatePlotId(pos.vchPoolPubKey, plotPubKey.Serialize());
    if (!passes_plot_filter(plotId, challenge, params.nMercuryPosFilterBits))
        return ::pos::VerifyResult::ErrorPlotFilter;

    // 3.verify signature
    bool fVerified = bls::AugSchemeMPL().Verify(
        plotPubKey,
        std::vector<uint8_t>(challenge.begin(), challenge.end()),
        bls::G2Element::FromByteVector(pos.vchSignature));
    if (!fVerified)
        return ::pos::VerifyResult::ErrorBLS;

    // 4.quality AND iterations
    auto quality = chiapos::ValidateProof(
        std::vector<uint8_t>(plotId.begin(), plotId.end()),
        static_cast<uint8_t>(pos.nPlotK),
        std::vector<uint8_t>(challenge.begin(), challenge.end()),
        pos.vchProof);
    if (quality.size() != 32)
        return ::pos::VerifyResult::ErrorPoS;
    static const arith_uint1024 bigDifficultyConstantFactor = arith_uint1024_shift(67);
    static const arith_uint1024 bigMax256 = arith_uint1024_shift(256);
    arith_uint1024 bigDifficulty = arith_uint1024(poc::INITIAL_BASE_TARGET / prevBlockIndex.nBaseTarget);
    arith_uint1024 bigQualityHash = UintToArith1024BE(sha256({ uint256(quality), challenge }));
    arith_uint1024 bigPlotSize = arith_uint1024(expected_plot_size(pos.nPlotK));
    arith_uint1024 bigIterations = (bigDifficulty * bigDifficultyConstantFactor * bigQualityHash) / (bigMax256 * bigPlotSize);

    iterations = bigIterations.GetLow64();
    if (iterations == 0)
        iterations = 1;

    return ::pos::VerifyResult::Success;
}

}

namespace pos {

std::string ToString(VerifyResult result)
{
    switch (result) {
    case VerifyResult::Success:
        return "success";
    case VerifyResult::ErrorPlotFilter:
        return "error-plotfilters";
    case VerifyResult::ErrorPoS:
        return "error-PoS";
    case VerifyResult::ErrorBLS:
        return "error-BLS";
    case VerifyResult::ErrorIterations:
        return "error-iterations";
    case VerifyResult::ErrorException:
        return "error-exception";
    case VerifyResult::Error:
    default:
        return "error";
    }
}

VerifyResult VerifyBlockHeader(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params)
{
    // 1.check params
    if (!check_pos(block.pos))
        return VerifyResult::Error;
    if (block.nPlotterId != ToFarmerId(block.pos.vchFarmerPubKey))
        return VerifyResult::Error;

    const uint256 challenge = CreateChallenge(prevBlockIndex.GetNextGenerationSignature(), block.pos.nScanIterations);

    // 2.verify
    uint64_t iterations = 0;
    try {
        VerifyResult result = VerifyAndGetIterations(iterations, prevBlockIndex, block.pos, challenge, params);
        if (result != VerifyResult::Success)
            return result;
    } catch (...) {
        return VerifyResult::ErrorException;
    }
    if (iterations != block.nNonce)
        return VerifyResult::ErrorIterations;

    return VerifyResult::Success;
}

VerifyResult VerifyAndUpdateBlockHeader(CBlockHeader& block, const CBlockIndex& prevBlockIndex, const Consensus::Params& params)
{
    // 1.check params
    if (!check_pos(block.pos))
        return VerifyResult::Error;

    const uint256 challenge = CreateChallenge(prevBlockIndex.GetNextGenerationSignature(), block.pos.nScanIterations);

    // 2.verify
    uint64_t nIterations = 0;
    try {
        VerifyResult result = VerifyAndGetIterations(nIterations, prevBlockIndex, block.pos, challenge, params);
        if (result != VerifyResult::Success)
            return result;
    } catch (...) {
        return VerifyResult::ErrorException;
    }

    block.nPlotterId = ToFarmerId(block.pos.vchFarmerPubKey);
    block.nNonce = nIterations;

    return VerifyResult::Success;
}

}
