// Copyright (c) 2021-2022 The Qitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POS_POS_H
#define BITCOIN_POS_POS_H

#include <pos/bls.h>
#include <uint256.h>

#include <string>
#include <vector>

class CBlockHeader;
class CBlockIndex;
class CProofOfSpace;

namespace Consensus { struct Params; }

namespace pos {

typedef std::vector<unsigned char> Bytes;

const static int32_t MIN_PLOT_SIZE = 32;
const static int32_t MAX_PLOT_SIZE = 50;

/** Create farmer private key by passphrase
*/
bls::PrivateKey GeneratePrivateKey(const std::string& passphrase);

/** Derive private key
*/
bls::PrivateKey DeriveMasterToFarmer(const bls::PrivateKey& privateKey);
bls::PrivateKey DeriveMasterToPool(const bls::PrivateKey& privateKey);
bls::PrivateKey DeriveMasterToLocal(const bls::PrivateKey& privateKey);

/** Convert farmer public key to farmer Id
*/
uint64_t ToFarmerId(const unsigned char farmerPublicKey[48]);
uint64_t ToFarmerId(const std::vector<unsigned char> &farmerPubKey);

/** Create plot id
*/
uint256 CreatePlotId(const Bytes& poolPubKey, const Bytes& plotPubKey);
uint256 CreatePlotId(const bls::G1Element& poolPubKey, const bls::G1Element& plotPubKey);

/** Convert plot id to hex string
*/
std::string ConvertPlotIdToString(const uint256& plotId);

/** Create plot public key
*/
bls::G1Element CreatePlotPubKey(const bls::G1Element& localPubKey, const bls::G1Element& farmerPubKey);
bls::G1Element CreatePlotPubKey(const bls::G1Element& localPubKey, const bls::G1Element& farmerPubKey, bool includeTaproot);
bls::G1Element CreatePlotPubKey(const bls::G1Element& localPubKey, const bls::G1Element& farmerPubKey, const bls::G1Element& taprootPubKey);

/** Create taproot sk
*/
bls::PrivateKey CreateTaprootPrivateKey(const bls::G1Element& localPubKey, const bls::G1Element& farmerPubKey);

/** Create challenge for iterations
*/
uint256 CreateChallenge(const uint256& challenge, int32_t scanIterations);

/** For VerifyBlockHeader and VerifyAndUpdateBlockHeader */
enum class VerifyResult {
    Success,
    Error,
    ErrorPlotFilter,
    ErrorPoS,
    ErrorBLS,
    ErrorIterations,
    ErrorException,
};

/** Convert VerifyResult to string */
std::string ToString(VerifyResult result);

/**
 * Verify PoS block
 *
 * @param prevBlockIndex    Previous block
 * @param block             Block header
 * @param params            Consensus params
 *
 * @return Return true when verify pass
 */
VerifyResult VerifyBlockHeader(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params);

/**
 * Verify and Update PoS to block
 *
 * @param block             Block header
 * @param prevBlockIndex    Previous block
 * @param params            Consensus params
 *
 * @return Return true when success
 */
VerifyResult VerifyAndUpdateBlockHeader(CBlockHeader& block, const CBlockIndex& prevBlockIndex, const Consensus::Params& params);

}

#endif