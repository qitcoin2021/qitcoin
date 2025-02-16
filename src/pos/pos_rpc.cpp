// Copyright (c) 2017-2020 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/pos.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <net.h>
#include <poc/poc.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <util/bip39.h>
#include <util/strencodings.h>
#include <univalue.h>
#include <validation.h>

#include <iomanip>
#include <sstream>

static UniValue pos_getMiningInfo(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "pos_getMiningInfo\n"
            "\nGet current mining information.\n"
            "\nResult:\n"
            "{\n"
            "  [ height ]                  (integer) Next block height\n"
            "  [ challenge ]               (string) Current mining challenge\n"
            "  [ difficulty ]              (string) Current mining difficulty \n"
            "  [ scan_iterations ]         (number) Scan Iterations \n"
            "  [ filter_bits ]             (number) Plot id filter bits \n"
            "  [ epoch ]                   (string) Next mining epoch time \n"
            "  [ now ]                     (number) Current server time \n"
            "}\n"
        );
    }

    UniValue result(UniValue::VOBJ);

    LOCK(cs_main);
    const CBlockIndex *pindexMining = ChainActive().Tip();
    if (pindexMining == nullptr || pindexMining->nHeight < 1)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block chain tip is empty!");

    if (pindexMining->nHeight != 1 && ChainstateActive().IsInitialBlockDownload())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Is initial block downloading!");

    int64_t now = GetTime();
    if ((pindexMining->nHeight == 1 && Params().GetConsensus().nBeginMiningTime > now)
        || pindexMining->nHeight < Params().GetConsensus().nMercuryActiveHeight)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Waiting for begining!");

    int64_t epoch = pindexMining->GetBlockTime();
    now = std::max(GetTime(), epoch);

    result.pushKV("height", pindexMining->nHeight + 1);
    result.pushKV("challenge", HexStr(pindexMining->GetNextGenerationSignature()));
    result.pushKV("difficulty", poc::INITIAL_BASE_TARGET / pindexMining->nBaseTarget);
    result.pushKV("scan_iterations", (uint64_t) ((now - epoch) / Params().GetConsensus().nPowTargetSpacing));
    result.pushKV("filter_bits", (uint64_t) Params().GetConsensus().nMercuryPosFilterBits);
    result.pushKV("epoch", (uint64_t) epoch);
    result.pushKV("now", (uint64_t) now);

    return result;
}

static UniValue pos_submitProof(const JSONRPCRequest& request)
{
    if (request.fHelp || !request.params.isObject()) {
        throw std::runtime_error(
            "pos_submitProof \"{}\"\n"
            "\nSubmit mining proof.\n"
            "\nArguments:\n"
            "1. \"payload\"         (object, required) Proof payload\n"
            "\nResult:\n"
            "{\n"
            "  [ deadline ]                (integer, optional) Current block generation signature\n"
            "  [ height ]                  (integer, optional) Target block height\n"
            "  [ targetDeadline ]          (number) Current acceptable deadline \n"
            "}\n"
        );
    }

    CChiaProofOfSpace pos;
    {
        uint256 rawChallenge(ParseHex(find_value(request.params, "challenge").get_str()));
        int nScanIterations = find_value(request.params, "scan_iterations").get_int();

        pos::Bytes farmerPrivateKeyBytes = ParseHex(find_value(request.params, "farmer_private_key").get_str());
        pos::Bytes poolPublicKeyBytes = ParseHex(find_value(request.params, "pool_public_key").get_str()); // OG or OP
        pos::Bytes localMasterPrivateKeyBytes = ParseHex(find_value(request.params, "security_key").get_str());
        int nPlotK = find_value(request.params, "plot_size").get_int();
        pos::Bytes proofBytes = ParseHex(find_value(request.params, "proof_xs").get_str());
        if (nScanIterations < 0
            || farmerPrivateKeyBytes.size() != bls::PrivateKey::PRIVATE_KEY_SIZE
            || (poolPublicKeyBytes.size() != bls::G1Element::SIZE && poolPublicKeyBytes.size() != 32)
            || localMasterPrivateKeyBytes.size() != bls::PrivateKey::PRIVATE_KEY_SIZE
            || nPlotK < pos::MIN_PLOT_SIZE || nPlotK > pos::MAX_PLOT_SIZE
            || proofBytes.empty()) {
            throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Proof Of Space!");
        }

        uint256 challenge = pos::CreateChallenge(rawChallenge, nScanIterations);
        auto vchChallenge = std::vector<uint8_t>(challenge.begin(), challenge.end());

        auto farmerPrivateKey = bls::PrivateKey::FromByteVector(farmerPrivateKeyBytes);
        auto farmerPublicKey = farmerPrivateKey.GetG1Element();
        auto localPrivateKey = pos::DeriveMasterToLocal(bls::PrivateKey::FromByteVector(localMasterPrivateKeyBytes));
        auto localPublicKey = localPrivateKey.GetG1Element();

        // agg
        if (poolPublicKeyBytes.size() == 32) {
            // OP (with taproot)
            auto taprootPrivateKey = pos::CreateTaprootPrivateKey(localPublicKey, farmerPublicKey);
            auto taprootPulicKey = taprootPrivateKey.GetG1Element();
            auto plotPublicKey = pos::CreatePlotPubKey(localPublicKey, farmerPublicKey, taprootPulicKey);
            auto farmerSignature = bls::AugSchemeMPL().Sign(farmerPrivateKey, vchChallenge, plotPublicKey);
            auto localSignature = bls::AugSchemeMPL().Sign(localPrivateKey, vchChallenge, plotPublicKey);
            auto taprootSignature = bls::AugSchemeMPL().Sign(taprootPrivateKey, vchChallenge, plotPublicKey);
            pos.vchSignature = bls::AugSchemeMPL().Aggregate({taprootSignature, localSignature, farmerSignature}).Serialize();
        } else {
            // OG
            auto plotPublicKey = pos::CreatePlotPubKey(localPublicKey, farmerPublicKey);
            auto farmerSignature = bls::AugSchemeMPL().Sign(farmerPrivateKey, vchChallenge, plotPublicKey);
            auto localSignature = bls::AugSchemeMPL().Sign(localPrivateKey, vchChallenge, plotPublicKey);
            pos.vchSignature = bls::AugSchemeMPL().Aggregate({localSignature, farmerSignature}).Serialize();
        }

        pos.nScanIterations = nScanIterations;
        pos.vchFarmerPubKey = farmerPublicKey.Serialize();
        pos.vchPoolPubKey = poolPublicKeyBytes;
        pos.vchLocalPubKey = localPublicKey.Serialize();
        pos.nPlotK = nPlotK;
        pos.vchProof = proofBytes;
    }

    int nTargetHeight = 0;
    UniValue vTargetHeight = find_value(request.params, "height");
    if (!vTargetHeight.isNull()) {
        nTargetHeight = vTargetHeight.isNum() ? vTargetHeight.get_int() : std::stoi(vTargetHeight.get_str());
    }

    std::string generateTo;
    UniValue vGenerateTo = find_value(request.params, "generate_to");
    if (!vGenerateTo.isNull()) {
        generateTo = vGenerateTo.get_str();
    }

    bool fCheckBind = true;
    UniValue vCheckBind = find_value(request.params, "check_to");
    if (!vGenerateTo.isNull()) {
        fCheckBind = vCheckBind.get_bool();
    }


    LOCK(cs_main);
    const CBlockIndex *pindexMining = ChainActive()[nTargetHeight < 1 ? ChainActive().Height() : (nTargetHeight - 1)];
    if (pindexMining == nullptr || pindexMining->nHeight < 1)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block chain tip is empty!");

    if (pindexMining->nHeight != 1 && ChainstateActive().IsInitialBlockDownload())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Is initial block downloading!");

    if (pindexMining->nHeight == 1 && Params().GetConsensus().nBeginMiningTime > GetTime())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Waiting for begining!");

    if (pindexMining->nHeight < Params().GetConsensus().nMercuryActiveHeight)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Waiting for begining!");

    UniValue result(UniValue::VOBJ);
    uint64_t bestDeadline = 0;
    uint64_t deadline = poc::AddProofOfSpace(bestDeadline, *pindexMining, pos, generateTo, fCheckBind, Params().GetConsensus());
    result.pushKV("result", "success");
    result.pushKV("deadline", deadline);
    result.pushKV("height", pindexMining->nHeight + 1);
    result.pushKV("targetDeadline", (bestDeadline == 0 ? poc::MAX_TARGET_DEADLINE : bestDeadline));
    return result;
}

static UniValue pos_getPlotterId(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "pos_getplotterid \"passphrase\"\n"
            "\nGet potter id from passphrase.\n"
            "\nArguments:\n"
            "1. \"passphrase\"      (string, required) The string of the passphrase\n"
            "\nResult:\n"
            "Plotter id\n"
        );
    }

    auto farmerPrivateKey = pos::DeriveMasterToFarmer(pos::GeneratePrivateKey(request.params[0].get_str()));
    auto farmerPublicKeyBytes = farmerPrivateKey.GetG1Element().Serialize();

    UniValue result(UniValue::VOBJ);
    result.pushKV("pubkey", HexStr(farmerPublicKeyBytes));
    result.pushKV("plotterId", std::to_string(pos::ToFarmerId(farmerPublicKeyBytes)));
    return result;
}

static UniValue pos_getNewPlotter(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "pos_getnewplotter\n"
            "\nGet new plotter account.\n"
            "\nResult:\n"
            "{\n"
            "  [ passphrase ]              (string) The passphrase\n"
            "  [ plotterId ]               (string) The plotter ID from passphrase\n"
            "}\n"
        );
    }

    auto passphrase = BIP39_JoinMnemonic(BIP39_GenMnemonic(24));
    auto farmerPrivateKey = pos::DeriveMasterToFarmer(pos::GeneratePrivateKey(passphrase));
    auto farmerPublicKeyBytes = farmerPrivateKey.GetG1Element().Serialize();

    UniValue result(UniValue::VOBJ);
    result.pushKV("passphrase", passphrase);
    result.pushKV("pubkey", HexStr(farmerPublicKeyBytes));
    result.pushKV("plotterId", std::to_string(pos::ToFarmerId(farmerPublicKeyBytes)));
    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)        argNames
  //  --------------------- ------------------------  ----------------------  ----------
    { "pos",                "pos_getMiningInfo",      &pos_getMiningInfo,     { } },
    { "pos",                "pos_submitProof",        &pos_submitProof,       { "payload", "height", "address", "checkBind" } },
    { "pos",                "pos_getplotterid",       &pos_getPlotterId,      { "passPhrase" } },
    { "pos",                "pos_getnewplotter",      &pos_getNewPlotter,     { } },
};

void RegisterPoSRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
