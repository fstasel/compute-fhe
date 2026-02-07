#pragma once

#include "binfhecontext.h"
#include <vector>

#include "CFHETypes.h"

#define COPY_CT(x) std::make_shared<LWECiphertextImpl>(*x)

using namespace lbcrypto;
using namespace std;
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

    uint PFixedPoint2uint(const PFixedPoint pt);
    PFixedPoint uint2PFixedPoint(uint pt, size_t n_digits = 8);
    CFixedPoint EncryptInt(uint pt, size_t n_digits = 8, bool fresh = true);
    uint DecryptInt(const CFixedPoint &ct, size_t n_digits = 0);
    CFixedPoint EncryptInt(PFixedPoint pt, size_t n_digits = 0, bool fresh = true);
    void DecryptInt(const CFixedPoint &ct, PFixedPoint &pt, size_t n_digits = 0);
    LWECiphertext EncryptBool(uint pt, bool fresh = true);
    uint DecryptBool(ConstLWECiphertext &ct);

    double extractNoise(ConstLWECiphertext &ct);

    void PrintCryptoContextParams();
    void PrintLWECiphertextParams(ConstLWECiphertext &ct);
};