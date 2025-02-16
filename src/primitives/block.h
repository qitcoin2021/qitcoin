// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <pubkey.h>
#include <serialize.h>
#include <uint256.h>

/** For Chia PoS.
 */
class CChiaProofOfSpace
{
public:
    std::vector<unsigned char> vchFarmerPubKey; // fpk[48]
    std::vector<unsigned char> vchPoolPubKey;  // ppk[48]/pph[32]
    std::vector<unsigned char> vchLocalPubKey; // local_pk[48]
    std::vector<unsigned char> vchProof;
    int32_t nPlotK;

    std::vector<unsigned char> vchSignature; // fk.sign(make(genSign,iterations), plot_pk)[96]
    int32_t nScanIterations;

    CChiaProofOfSpace()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(LIMITED_VECTOR(vchFarmerPubKey, 48));
        READWRITE(LIMITED_VECTOR(vchPoolPubKey, 48)); // max(48, 32)
        READWRITE(LIMITED_VECTOR(vchLocalPubKey, 48));
        READWRITE(LIMITED_VECTOR(vchProof, 1024));
        READWRITE(nPlotK);

        READWRITE(LIMITED_VECTOR(vchSignature, 96));
        READWRITE(nScanIterations);
    }

    void SetNull()
    {
        vchFarmerPubKey.clear();
        vchPoolPubKey.clear();
        vchLocalPubKey.clear();
        vchProof.clear();
        nPlotK = 0;

        vchSignature.clear();
        nScanIterations = 0;
    }

    bool IsNull() const
    {
        return vchFarmerPubKey.empty()
            && vchPoolPubKey.empty()
            && vchLocalPubKey.empty()
            && vchProof.empty()
            && nPlotK == 0
            && vchSignature.empty()
            && nScanIterations == 0;
    }

    bool IsValid() const
    {
        return vchFarmerPubKey.size() == 48
            && (vchPoolPubKey.size() == 48 || vchPoolPubKey.size() == 32)
            && vchLocalPubKey.size() == 48
            && !vchProof.empty()
            && nPlotK > 0 && nPlotK < 0x7fff
            && vchSignature.size() == 96
            && nScanIterations >= 0 && nScanIterations < 0x7fffffff;
    }
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint64_t nBaseTarget;
    uint64_t nNonce;     //! nonce or iterations
    uint64_t nPlotterId; //! plotter or farmer

    // Chia PoS
    CChiaProofOfSpace pos;

    // block signature by generator
    std::vector<unsigned char> vchPubKey;
    std::vector<unsigned char> vchSignature;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint64_t nFlags = nBaseTarget & 0x0000ffffffffffffL;
        // add flags
        nFlags |= pos.IsNull() ? 0 : 0x4000000000000000L;
        nFlags |= vchPubKey.empty() ? 0 : 0x8000000000000000L;

        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nFlags);
        READWRITE(nNonce);
        READWRITE(nPlotterId);

        // remove flags
        nBaseTarget = nFlags & 0x0000ffffffffffffL;

        // Chia PoS support
        if (nFlags & 0x4000000000000000L) {
            READWRITE(pos);
        }

        // signature support
        if (nFlags & 0x8000000000000000L) {
            READWRITE(LIMITED_VECTOR(vchPubKey, CPubKey::COMPRESSED_PUBLIC_KEY_SIZE));

            // Signature raw data exclude vchSignature
            if (!(GetSerializeType(s) & SER_UNSIGNATURED)) {
                READWRITE(LIMITED_VECTOR(vchSignature, CPubKey::SIGNATURE_SIZE));
            }
        }
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBaseTarget = 0;
        nNonce = 0;
        nPlotterId = 0;
        pos.SetNull();
        vchPubKey.clear();
        vchSignature.clear();
    }

    bool IsNull() const
    {
        return (nBaseTarget == 0);
    }

    uint256 GetHash() const;
    uint256 GetUnsignaturedHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(CBlockHeader, *this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBaseTarget    = nBaseTarget;
        block.nNonce         = nNonce;
        block.nPlotterId     = nPlotterId;
        block.pos            = pos;
        block.vchPubKey      = vchPubKey;
        block.vchSignature   = vchSignature;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
