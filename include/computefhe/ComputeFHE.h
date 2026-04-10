#pragma once

#include <openfhe/binfhe/binfhecontext.h>
#include <vector>

#include <computefhe/ALUGateLogic.h>
#include <computefhe/ALUOptimized.h>
#include <computefhe/BaseALU.h>
#include <computefhe/BaseALUSimulator.h>
#include <computefhe/CFHETypes.h>
#include <computefhe/CFHE_FixedPoint.h>
#include <computefhe/CFHE_Integer.h>
#include <computefhe/ConditionManager.h>
#include <computefhe/Evector.h>
#include <computefhe/FixedPoint.h>
#include <computefhe/SimGateLogic.h>
#include <computefhe/SimOptimized.h>

using namespace lbcrypto;
using namespace std;

namespace computefhe {

    class ComputeFHE {
      private:
        CryptoContextParam cc_param;
        ALUType alu_type;
        BinFHEContext cc;
        LWEPrivateKey sk;
        BaseALU *alu;
        bool sim_mode;

        void createCC();
        void createALU();

      public:
        ComputeFHE(bool simulation_mode = false);
        ComputeFHE(CryptoContextParam param, bool simulation_mode = false);
        ComputeFHE(CryptoContextParam param, ALUType alu_type,
                   bool simulation_mode = false);
        ComputeFHE(ALUType alu_type, bool simulation_mode = false);
        ~ComputeFHE();

        BinFHEContext &GetBinFHEContext();
        BaseALU *GetALU();
        BaseALUSimulator *GetSimulator();
        CryptoContextParam GetCryptoContextParam();
        ALUType GetALUType();
        const LWEPrivateKey &GetLWEPrivateKey();
        void generateKeys();

        FixedPoint EncryptInt(uint64_t pt, size_t n_digits = 8,
                              bool fresh = true);
        uint64_t DecryptInt(const FixedPoint &ct, size_t n_digits = 0);
        BinaryDigit EncryptBool(bool pt, bool fresh = true);
        bool DecryptBool(const BinaryDigit &ct);
        FixedPoint GetConstantInt(uint64_t pt, size_t n_digits = 8);

        double extractNoise(ConstLWECiphertext &ct);

        void PrintCryptoContextParams();
        void PrintLWECiphertextParams(ConstLWECiphertext &ct);
    };
} // namespace computefhe
