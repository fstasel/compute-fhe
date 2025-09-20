#pragma once

#include "binfhecontext.h"
#include <vector>

#include "CFHETypes.h"

#define COPY_CT(x) std::make_shared<LWECiphertextImpl>(*x)

using namespace lbcrypto;
using namespace std;
using FixedPoint = vector<LWECiphertext>;

class TestReport
{
public:
    TestResult test_result = TR_FAIL;
    double delta_t = 0.;
};

class BaseArithmeticsEngine;

class ComputeFHE
{
private:
    CryptoContextParam cc_param;
    ArithmeticsEngineType ae_type;
    BinFHEContext cc;
    LWEPrivateKey sk;
    BaseArithmeticsEngine *ae;

    random_device rd;
    mt19937 gen;
    uniform_int_distribution<uint> dis;
    uint num_test = 1000;
    TimeVar t0;
    uint verbosity = 0;
    bool test_fresh = false;

    void createCC();
    void generateKeys();
    void createAE();
    void initRandomGenerator(uint max);
    double extractNoise(ConstLWECiphertext &ct);

public:
    ComputeFHE();
    ComputeFHE(CryptoContextParam param);
    ComputeFHE(CryptoContextParam param, ArithmeticsEngineType engine_type);
    ComputeFHE(ArithmeticsEngineType engine_type);
    ~ComputeFHE();

    BinFHEContext &GetBinFHEContext();
    CryptoContextParam GetCryptoContextParam();
    ArithmeticsEngineType GetArithmeticsEngineType();
    const LWEPrivateKey &GetLWEPrivateKey();

    uint CreateRandomNumber();
    void StartTimer();
    double ReadTimer();
    uint GetNumTest();
    void SetNumTest(uint n);
    uint GetVerbosity();
    void SetVerbosity(uint v);
    bool GetTestFresh();
    void SetTestFresh(bool val);

    FixedPoint EncryptInt(uint pt, size_t n_digits = 8, bool fresh = true);
    uint DecryptInt(const FixedPoint &ct, size_t n_digits = 0);
    LWECiphertext EncryptBool(uint pt, bool fresh = true);
    uint DecryptBool(ConstLWECiphertext &ct);

    void PrintCryptoContextParams();
    void PrintLWECiphertextParams(ConstLWECiphertext &ct);

    void StartTest(TestType tt, size_t n_digits = 8);
    TestReport TestEncryptDecrypt(size_t n_digits);

    void PrintTestReport(TestReport report, int64_t n, int64_t result);
    void PrintTestReport(TestReport report, int64_t n, int64_t result, int64_t expected);
    void PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t result, int64_t expected);
    void PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t n3, int64_t result, int64_t expected);

    void StartNoiseTest();

    static void TestAll();
    static void TestAllNoise();
    static void Test(ComputeFHE &c);
    static void TestNoise(ComputeFHE &c);
};