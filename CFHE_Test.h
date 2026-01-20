#pragma once

#include "ComputeFHE.h"
#include "CFHE_TestTypes.h"

using namespace std;

class TestReport
{
public:
    TestResult test_result = TR_FAIL;
    double delta_t = 0.;
};

class CFHE_Test
{
private:
    ComputeFHE *cfhe_base;

    random_device rd;
    mt19937 gen;
    uniform_int_distribution<uint> dis;
    uint num_test = 1000;
    TimeVar t0;
    uint verbosity = 0;
    bool test_fresh = false;
    bool regenerate_keys = true;

    void initRandomGenerator(uint max);
    void regenerateKeys();

public:
    CFHE_Test(CryptoContextParam param, ArithmeticsEngineType engine_type);

    uint CreateRandomNumber();
    void StartTimer();
    double ReadTimer();
    uint GetNumTest();
    void SetNumTest(uint n);
    uint GetVerbosity();
    void SetVerbosity(uint v);
    bool GetTestFresh();
    void SetTestFresh(bool val);
    bool GetRegenerateKeys();
    void SetRegenerateKeys(bool val);
    ComputeFHE *GetBase();

    void Test(TestType tt, size_t n_digits = 8);
    TestReport TestEncryptDecrypt(size_t n_digits);
    TestReport TestPFixedPointEncryptDecrypt(size_t n_digits);

    void PrintTestReport(TestReport report, int64_t n, int64_t result);
    void PrintTestReport(TestReport report, int64_t n, int64_t result, int64_t expected);
    void PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t result, int64_t expected);
    void PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t n3, int64_t result, int64_t expected);

    TestReport TestHalfAdder();
    TestReport TestHalfAdder_CP();
    TestReport TestFullAdder();
    TestReport TestFullAdder_CPP();
    TestReport TestFullAdder_CCP();
    TestReport TestXOR3();
    TestReport TestMulAdd();
    TestReport TestAdd(uint n_digits);
    TestReport TestPAdd(uint n_digits);
    TestReport TestAddC(uint n_digits);
    TestReport TestPAddC(uint n_digits);
    TestReport TestAddNC(uint n_digits);
    TestReport TestPAddNC(uint n_digits);
    TestReport TestAddCNC(uint n_digits);
    TestReport TestPAddCNC(uint n_digits);
    TestReport TestSub(uint n_digits);
    TestReport TestCPSub(uint n_digits);
    TestReport TestPSub(uint n_digits);
    TestReport TestSubC(uint n_digits);
    TestReport TestCPSubC(uint n_digits);
    TestReport TestPSubC(uint n_digits);
    TestReport TestSubNC(uint n_digits);
    TestReport TestCPSubNC(uint n_digits);
    TestReport TestPSubNC(uint n_digits);
    TestReport TestSubCNC(uint n_digits);
    TestReport TestCPSubCNC(uint n_digits);
    TestReport TestPSubCNC(uint n_digits);
    TestReport TestNeg(uint n_digits);
    TestReport TestCmpNotEq(uint n_digits);
    TestReport TestPCmpNotEq(uint n_digits);
    TestReport TestCmpEq(uint n_digits);
    TestReport TestPCmpEq(uint n_digits);
    TestReport TestCmpLTEq_U(uint n_digits);
    TestReport TestPCmpLTEq_U(uint n_digits);
    TestReport TestCmpGT_U(uint n_digits);
    TestReport TestPCmpGT_U(uint n_digits);
    TestReport TestCmpGTEq_U(uint n_digits);
    TestReport TestPCmpGTEq_U(uint n_digits);
    TestReport TestCmpLT_U(uint n_digits);
    TestReport TestPCmpLT_U(uint n_digits);
    TestReport TestCmpLTEq(uint n_digits);
    TestReport TestPCmpLTEq(uint n_digits);
    TestReport TestCmpGT(uint n_digits);
    TestReport TestPCmpGT(uint n_digits);
    TestReport TestCmpGTEq(uint n_digits);
    TestReport TestPCmpGTEq(uint n_digits);
    TestReport TestCmpLT(uint n_digits);
    TestReport TestPCmpLT(uint n_digits);
    TestReport TestFullMul(uint n_digits);
    TestReport TestPFullMul(uint n_digits);
    TestReport TestPFullMulFast(uint n_digits);
    TestReport TestBoothsMul(uint n_digits);
    TestReport TestMul(uint n_digits);
    TestReport TestPMul(uint n_digits);
    TestReport TestPMulFast(uint n_digits);

    void StartNoiseTest();
    void StartTest();

    static void TestAll();
    static void TestAllNoise();
};