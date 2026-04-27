#pragma once

#include <openfhe/binfhe/binfhecontext.h>
#include <vector>

#include <computefhe/ALUOptimized.h>
#include <computefhe/ALUStandard.h>
#include <computefhe/BaseALU.h>
#include <computefhe/BaseALUSimulator.h>
#include <computefhe/CFHETypes.h>
#include <computefhe/ConditionManager.h>
#include <computefhe/Efixedpoint.h>
#include <computefhe/Einteger.h>
#include <computefhe/Evector.h>
#include <computefhe/FixedPoint.h>
#include <computefhe/SimOptimized.h>
#include <computefhe/SimStandard.h>

using namespace lbcrypto;
using namespace std;

namespace computefhe {
    extern ComputeFHE *cfhe_base;
    extern bool CLIENT_MODE;

    void Init(CryptoContextParam cc_param = CCPARAM_STD128_3,
              ALUType alu_type = ALU_OPTIMIZED, bool client_mode = false,
              bool simulation_mode = false);
    void Finalize();

    class ComputeFHE {
      private:
        CryptoContextParam cc_param;
        ALUType alu_type;
        BinFHEContext cc;
        LWEPrivateKey sk;
        BaseALU *alu;
        bool sim_mode;
        bool auto_encrypt_mode;

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
        uint64_t ConvertConstantInt(const FixedPoint &pt);

        double extractNoise(ConstLWECiphertext &ct);

        void PrintCryptoContextParams();
        void PrintLWECiphertextParams(ConstLWECiphertext &ct);

        bool isAutoEncryptMode();
        void setAutoEncryptMode(bool mode = true);
    };
} // namespace computefhe
