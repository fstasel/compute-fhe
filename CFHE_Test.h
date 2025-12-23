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

    void Test(TestType tt, size_t n_digits = 8);
    TestReport TestEncryptDecrypt(size_t n_digits);

    void PrintTestReport(TestReport report, int64_t n, int64_t result);
    void PrintTestReport(TestReport report, int64_t n, int64_t result, int64_t expected);
    void PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t result, int64_t expected);
    void PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t n3, int64_t result, int64_t expected);

    TestReport TestHalfAdder();
    TestReport TestFullAdder();
    TestReport TestXOR3();
    TestReport TestMulAdd();
    TestReport TestAdd(uint n_digits);
    TestReport TestAddC(uint n_digits);
    TestReport TestAddNC(uint n_digits);
    TestReport TestSub(uint n_digits);
    TestReport TestSubC(uint n_digits);
    TestReport TestSubNC(uint n_digits);
    TestReport TestNeg(uint n_digits);
    TestReport TestCmpNotEq(uint n_digits);
    TestReport TestCmpEq(uint n_digits);
    TestReport TestCmpLTEq_U(uint n_digits);
    TestReport TestCmpGT_U(uint n_digits);
    TestReport TestCmpGTEq_U(uint n_digits);
    TestReport TestCmpLT_U(uint n_digits);
    TestReport TestCmpLTEq(uint n_digits);
    TestReport TestCmpGT(uint n_digits);
    TestReport TestCmpGTEq(uint n_digits);
    TestReport TestCmpLT(uint n_digits);
    TestReport TestFullMul(uint n_digits);
    TestReport TestMul(uint n_digits);

    void StartNoiseTest();
    void StartTest();

    static void TestAll();
    static void TestAllNoise();
};