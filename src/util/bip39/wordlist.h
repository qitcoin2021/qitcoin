// Copyright (c) 2017-2020 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BIP39_WORDLIST_H
#define BITCOIN_UTIL_BIP39_WORDLIST_H

#include <string>
#include <vector>

typedef std::string CBIP39String;
typedef std::vector<CBIP39String> CBIP39WordList;

extern CBIP39WordList bip39_wordlist_english;


#endif // BITCOIN_UTIL_BIP39_WORDLIST_H
