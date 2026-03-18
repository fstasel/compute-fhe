#pragma once

#include <openfhe/binfhe/binfhecontext.h>
#include <vector>

#include <computefhe/CFHETypes.h>

#define COPY_CT(x) std::make_shared<LWECiphertextImpl>(*x)

using namespace lbcrypto;
using namespace std;

namespace computefhe
{

    using CFixedPoint = vector<LWECiphertext>;
    using PFixedPoint = vector<LWEPlaintext>;

    class BaseArithmeticsEngine;
    class BaseAESimulator;

    class ComputeFHE
    {
    private:
        CryptoContextParam cc_param;
        ArithmeticsEngineType ae_type;
        BinFHEContext cc;
        LWEPrivateKey sk;
        BaseArithmeticsEngine *ae;
        BaseAESimulator *sim;

        void createCC();
        void createAE();
        void createSim();

    public:
        ComputeFHE();
        ComputeFHE(CryptoContextParam param);
        ComputeFHE(CryptoContextParam param, ArithmeticsEngineType engine_type);
        ComputeFHE(ArithmeticsEngineType engine_type);
        ~ComputeFHE();

        BinFHEContext &GetBinFHEContext();
        BaseArithmeticsEngine *GetArithmeticsEngine();
        BaseAESimulator *GetSimulator();
        CryptoContextParam GetCryptoContextParam();
        ArithmeticsEngineType GetArithmeticsEngineType();
        const LWEPrivateKey &GetLWEPrivateKey();
        void generateKeys();

        uint64_t PFixedPoint2uint(const PFixedPoint pt);
        PFixedPoint uint2PFixedPoint(uint64_t pt, size_t n_digits = 8);

        CFixedPoint EncryptInt(uint64_t pt, size_t n_digits = 8, bool fresh = true);
        uint64_t DecryptInt(const CFixedPoint &ct, size_t n_digits = 0);
        CFixedPoint EncryptInt(PFixedPoint pt, size_t n_digits = 0, bool fresh = true);
        void DecryptInt(const CFixedPoint &ct, PFixedPoint &pt, size_t n_digits = 0);
        LWECiphertext EncryptBool(bool pt, bool fresh = true);
        bool DecryptBool(ConstLWECiphertext &ct);

        CFixedPoint GetConstantInt(uint64_t pt, size_t n_digits = 8);

        double extractNoise(ConstLWECiphertext &ct);

        void PrintCryptoContextParams();
        void PrintLWECiphertextParams(ConstLWECiphertext &ct);
    };
}