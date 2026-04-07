#pragma once

#include <openfhe/binfhe/binfhecontext.h>
#include <vector>

#include <computefhe/CFHETypes.h>

#define COPY_CT(x) std::make_shared<LWECiphertextImpl>(*x)

using namespace lbcrypto;
using namespace std;

namespace computefhe {

    using FixedPoint = vector<LWECiphertext>;

    class BaseALU;

    class ComputeFHE {
      private:
        CryptoContextParam cc_param;
        ALUType alu_type;
        BinFHEContext cc;
        LWEPrivateKey sk;
        BaseALU *alu;

        void createCC();
        void createALU();

      public:
        ComputeFHE();
        ComputeFHE(CryptoContextParam param);
        ComputeFHE(CryptoContextParam param, ALUType alu_type);
        ComputeFHE(ALUType alu_type);
        ~ComputeFHE();

        BinFHEContext &GetBinFHEContext();
        BaseALU *GetALU();
        CryptoContextParam GetCryptoContextParam();
        ALUType GetALUType();
        const LWEPrivateKey &GetLWEPrivateKey();
        void generateKeys();

        FixedPoint EncryptInt(uint64_t pt, size_t n_digits = 8,
                              bool fresh = true);
        uint64_t DecryptInt(const FixedPoint &ct, size_t n_digits = 0);
        LWECiphertext EncryptBool(bool pt, bool fresh = true);
        bool DecryptBool(ConstLWECiphertext &ct);
        FixedPoint GetConstantInt(uint64_t pt, size_t n_digits = 8);

        double extractNoise(ConstLWECiphertext &ct);

        void PrintCryptoContextParams();
        void PrintLWECiphertextParams(ConstLWECiphertext &ct);
    };
} // namespace computefhe