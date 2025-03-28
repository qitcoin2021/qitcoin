// Copyright (c) 2017-2020 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <poc/poc.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <net.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <util/strencodings.h>
#include <univalue.h>
#include <validation.h>

#include <iomanip>
#include <sstream>

static UniValue addSignPrivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "addsignprivkey \"privkey\"\n"
            "\nAdd private key for signature.\n"
            "\nArguments:\n"
            "1. \"privkey\"      (string, required) The string of the private key\n"
            "\nResult:\n"
            "Qitcoin mining address\n"
        );
    }

    CKey key = DecodeSecret(request.params[0].get_str());
    if (!key.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");

    CTxDestination dest = poc::AddMiningSignaturePrivkey(key);
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    return EncodeDestination(dest);
}

static UniValue listSignAddresses(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "listsignaddresses\n"
            "\nList signature addresses for signature.\n"
            "\nResult:\n"
            "Qitcoin address\n"
        );
    }

    UniValue addresses(UniValue::VARR);
    for (const CTxDestination &dest : poc::GetMiningSignatureAddresses()) {
        addresses.push_back(EncodeDestination(dest));
    }

    return addresses;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)                  argNames
  //  --------------------- ------------------------  ----------------------  ----------
    { "poc",                "addsignprivkey",         &addSignPrivkey,        { "privkey" } },
    { "poc",                "listsignaddresses",      &listSignAddresses,     { } },
};

void RegisterPoCRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
