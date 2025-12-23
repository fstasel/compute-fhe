#pragma once

#include "binfhecontext.h"
#include <vector>

#include "CFHETypes.h"

#define COPY_CT(x) std::make_shared<LWECiphertextImpl>(*x)

using namespace lbcrypto;
using namespace std;
using FixedPoint = vector<LWECiphertext>;

class BaseArithmeticsEngine;

class ComputeFHE
{
private:
    CryptoContextParam cc_param;
    ArithmeticsEngineType ae_type;
    BinFHEContext cc;
    LWEPrivateKey sk;
    BaseArithmeticsEngine *ae;

    void createCC();
    void createAE();

public:
    ComputeFHE();
    ComputeFHE(CryptoContextParam param);
    ComputeFHE(CryptoContextParam param, ArithmeticsEngineType engine_type);
    ComputeFHE(ArithmeticsEngineType engine_type);
    ~ComputeFHE();

    BinFHEContext &GetBinFHEContext();
    BaseArithmeticsEngine *GetArithmeticsEngine();
    CryptoContextParam GetCryptoContextParam();
    ArithmeticsEngineType GetArithmeticsEngineType();
    const LWEPrivateKey &GetLWEPrivateKey();
    void generateKeys();

    FixedPoint EncryptInt(uint pt, size_t n_digits = 8, bool fresh = true);
    uint DecryptInt(const FixedPoint &ct, size_t n_digits = 0);
    LWECiphertext EncryptBool(uint pt, bool fresh = true);
    uint DecryptBool(ConstLWECiphertext &ct);

    double extractNoise(ConstLWECiphertext &ct);

    void PrintCryptoContextParams();
    void PrintLWECiphertextParams(ConstLWECiphertext &ct);
};