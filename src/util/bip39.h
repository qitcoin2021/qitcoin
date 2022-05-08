// Copyright (c) 2017-2020 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BIP39_H
#define BITCOIN_UTIL_BIP39_H

#include <attributes.h>
#include <util/bip39/wordlist.h>

#include <string>
#include <vector>

/** Generate BIP39 seed by mnemonic and password. */
std::vector<unsigned char> BIP39_MnemonicToSeed(const std::string& mnemonic, const std::string& password);

/** Generate BIP39 mnemonic. */
CBIP39WordList BIP39_GenMnemonic(int words);

/** Join BIP39 mnemonic to string. */
CBIP39String BIP39_JoinMnemonic(const CBIP39WordList& wordlist);

#endif // BITCOIN_UTIL_BIP39_H
