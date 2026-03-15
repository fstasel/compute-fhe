#include "include/CFHE_Test.h"

#include <iostream>
using namespace std;
using namespace computefhe_test;

void CFHE_Test::regenerateKeys()
{
    if (verbosity >= 4)
    {
        cout << "Generating the bootstrapping keys..." << endl;
    }
    cfhe_base->GetBinFHEContext().ClearBTKeys();
    cfhe_base->generateKeys();
    if (verbosity >= 4)
    {
        cout << "Completed the key generation." << endl;
    }
}

void CFHE_Test::initRandomGenerator(uint max)
{
    gen = mt19937(rd());
    dis = uniform_int_distribution<uint>(0, max);
}

void CFHE_Test::StartTimer()
{
    t0 = timeNow();
}

double CFHE_Test::ReadTimer()
{
    return (timeNow() - t0).count() / 1e6;
}

CFHE_Test::CFHE_Test(CryptoContextParam param, ArithmeticsEngineType engine_type)
{
    initRandomGenerator(UINT32_MAX);
    cout << "Creating ComputeFHE instance..." << endl;
    cfhe_base = new ComputeFHE(param, engine_type);
    cout << "done!" << endl;
}

uint CFHE_Test::GetNumTest()
{
    return num_test;
}

void CFHE_Test::SetNumTest(uint n)
{
    num_test = n;
}

uint CFHE_Test::GetVerbosity()
{
    return verbosity;
}

void CFHE_Test::SetVerbosity(uint v)
{
    verbosity = (v <= 4) ? v : 4;
}

bool CFHE_Test::GetTestFresh()
{
    return test_fresh;
}

void CFHE_Test::SetTestFresh(bool val)
{
    test_fresh = val;
}

bool CFHE_Test::GetRegenerateKeys()
{
    return regenerate_keys;
}

void CFHE_Test::SetRegenerateKeys(bool val)
{
    regenerate_keys = val;
}

uint CFHE_Test::CreateRandomNumber()
{
    return dis(gen);
}

void CFHE_Test::Test(TestType tt, size_t n_digits)
{
    cout << "cc_param: " << ToString(cfhe_base->GetCryptoContextParam())
         << " ae_type: " << ToString(cfhe_base->GetArithmeticsEngineType())
         << " test_type: " << ToString(tt)
         << " trials: " << num_test
         << " n_digits: " << n_digits << endl;

    initRandomGenerator((1UL << n_digits) - 1);
    uint n_error = 0;
    double t_time = 0, avg_t = 0, err_rate = 0;
    TestReport report;
    for (uint trial = 0; trial < num_test; trial++)
    {
        if (regenerate_keys)
        {
            regenerateKeys();
        }
        //
        switch (tt)
        {
        case TT_ENCRYPT_DECRYPT:
            report = TestEncryptDecrypt(n_digits);
            break;

        case TT_HA:
            report = TestHalfAdder();
            break;

        case TT_FA:
            report = TestFullAdder();
            break;

        case TT_XOR3:
            report = TestXOR3();
            break;

        case TT_MULADD:
            report = TestMulAdd();
            break;

        case TT_ADD:
            report = TestAdd(n_digits);
            break;

        case TT_ADDC:
            report = TestAddC(n_digits);
            break;

        case TT_ADD_NC:
            report = TestAddNC(n_digits);
            break;

        case TT_SUB:
            report = TestSub(n_digits);
            break;

        case TT_SUBC:
            report = TestSubC(n_digits);
            break;

        case TT_SUB_NC:
            report = TestSubNC(n_digits);
            break;

        case TT_NEG:
            report = TestNeg(n_digits);
            break;

        case TT_CMPNOTEQ:
            report = TestCmpNotEq(n_digits);
            break;

        case TT_CMPEQ:
            report = TestCmpEq(n_digits);
            break;

        case TT_CMPLTEQ_U:
            report = TestCmpLTEq_U(n_digits);
            break;

        case TT_CMPGT_U:
            report = TestCmpGT_U(n_digits);
            break;

        case TT_CMPGTEQ_U:
            report = TestCmpGTEq_U(n_digits);
            break;

        case TT_CMPLT_U:
            report = TestCmpLT_U(n_digits);
            break;

        case TT_CMPLTEQ:
            report = TestCmpLTEq(n_digits);
            break;

        case TT_CMPGT:
            report = TestCmpGT(n_digits);
            break;

        case TT_CMPGTEQ:
            report = TestCmpGTEq(n_digits);
            break;

        case TT_CMPLT:
            report = TestCmpLT(n_digits);
            break;

        case TT_FULLMUL:
            report = TestFullMul(n_digits);
            break;

        case TT_MUL:
            report = TestMul(n_digits);
            break;

        default:
            report = TestReport();
        }
        if (report.test_result == TR_FAIL)
        {
            n_error++;
        }
        t_time += report.delta_t;
        avg_t = t_time / (trial + 1);
        err_rate = (double)n_error / (trial + 1);
        if (verbosity >= 1)
        {
            cout << "Trial #" << (trial + 1)
                 << ": delta_t: " << report.delta_t << " ms"
                 << " error_rate: " << err_rate
                 << " avg_time: " << avg_t << " ms" << endl;
        }
    }
    cout << "error_rate: " << err_rate
         << " avg_time: " << avg_t << " ms" << endl;
}

TestReport CFHE_Test::TestEncryptDecrypt(size_t n_digits)
{
    TestReport report;
    uint n = CreateRandomNumber();
    StartTimer();
    FixedPoint ct = cfhe_base->EncryptInt(n, n_digits, test_fresh);
    uint result = cfhe_base->DecryptInt(ct);
    report.delta_t = ReadTimer();
    report.test_result = (n == result) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n, result);
    return report;
}

void CFHE_Test::PrintTestReport(TestReport report, int64_t n, int64_t result)
{
    if (verbosity >= 3 && report.test_result == TR_SUCCESS)
    {
        cout << "*** SUCCESS: ";
    }
    if (verbosity >= 2 && report.test_result == TR_FAIL)
    {
        cout << "*** FAILED: ";
    }
    if (verbosity >= 2 && report.test_result == TR_FAIL ||
        verbosity >= 3 && report.test_result == TR_SUCCESS)
    {
        cout << "n: " << n << " result: " << result << endl;
    }
}

void CFHE_Test::PrintTestReport(TestReport report, int64_t n, int64_t result, int64_t expected)
{
    if (verbosity >= 3 && report.test_result == TR_SUCCESS)
    {
        cout << "*** SUCCESS: ";
    }
    if (verbosity >= 2 && report.test_result == TR_FAIL)
    {
        cout << "*** FAILED: ";
    }
    if (verbosity >= 2 && report.test_result == TR_FAIL ||
        verbosity >= 3 && report.test_result == TR_SUCCESS)
    {
        cout << "n: " << n
             << " result: " << result
             << " expected: " << expected << endl;
    }
}

void CFHE_Test::PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t result, int64_t expected)
{
    if (verbosity >= 3 && report.test_result == TR_SUCCESS)
    {
        cout << "*** SUCCESS: ";
    }
    if (verbosity >= 2 && report.test_result == TR_FAIL)
    {
        cout << "*** FAILED: ";
    }
    if (verbosity >= 2 && report.test_result == TR_FAIL ||
        verbosity >= 3 && report.test_result == TR_SUCCESS)
    {
        cout << "n1: " << n1
             << " n2: " << n2
             << " result: " << result
             << " expected: " << expected << endl;
    }
}

void CFHE_Test::PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t n3, int64_t result, int64_t expected)
{
    if (verbosity >= 3 && report.test_result == TR_SUCCESS)
    {
        cout << "*** SUCCESS: ";
    }
    if (verbosity >= 2 && report.test_result == TR_FAIL)
    {
        cout << "*** FAILED: ";
    }
    if (verbosity >= 2 && report.test_result == TR_FAIL ||
        verbosity >= 3 && report.test_result == TR_SUCCESS)
    {
        cout << "n1: " << n1
             << " n2: " << n2
             << " n3: " << n3
             << " result: " << result
             << " expected: " << expected << endl;
    }
}

void CFHE_Test::StartNoiseTest()
{
    cout << "cc_param: " << ToString(cfhe_base->GetCryptoContextParam())
         << " ae_type: " << ToString(cfhe_base->GetArithmeticsEngineType())
         << " test_type: NOISE"
         << " trials: " << num_test << endl;

    double sum_fresh = 0, sum_bs = 0, noise, noise_bs;
    double delta_t = 0, t_time = 0, avg_t = 0;

    for (uint trial = 1; trial <= num_test; trial++)
    {
        if (regenerate_keys)
        {
            regenerateKeys();
        }
        //
        LWECiphertext ct = cfhe_base->GetBinFHEContext().Encrypt(cfhe_base->GetLWEPrivateKey(), CreateRandomNumber() % 2, FRESH);
        //
        StartTimer();
        LWECiphertext ct_bs = cfhe_base->GetBinFHEContext().Bootstrap(ct);
        delta_t = ReadTimer();
        //
        noise = cfhe_base->extractNoise(ct);
        noise_bs = cfhe_base->extractNoise(ct_bs);
        sum_fresh += noise * noise;
        sum_bs += noise_bs * noise_bs;
        t_time += delta_t;
        avg_t = t_time / trial;
        //
        if (verbosity >= 1)
        {
            cout << "Trial #" << trial
                 << ": fresh: " << noise << " bs: " << noise_bs
                 << " delta_t: " << delta_t << " ms"
                 << " avg_time: " << avg_t << " ms" << endl;
        }
    }
    double var_fresh = sum_fresh / num_test;
    double var_bs = sum_bs / num_test;
    //
    cout << "Variance_fresh: " << var_fresh << endl
         << "Variance_bootstrapped: " << var_bs << endl
         << "Average bs time: " << avg_t << " ms" << endl;
}

void CFHE_Test::StartTest()
{
    // StartTest(TT_ENCRYPT_DECRYPT);
    Test(TT_HA, 1);
    Test(TT_FA, 1);
    Test(TT_XOR3, 1);
    Test(TT_MULADD, 1);
    for (uint d = 2; d <= 4U; d <<= 1)
    {
        Test(TT_ADD, d);
        Test(TT_ADDC, d);
        Test(TT_ADD_NC, d);
        Test(TT_SUB, d);
        Test(TT_SUBC, d);
        Test(TT_SUB_NC, d);
        Test(TT_NEG, d);
        Test(TT_CMPNOTEQ, d);
        Test(TT_CMPEQ, d);
        Test(TT_CMPLTEQ_U, d);
        Test(TT_CMPGT_U, d);
        Test(TT_CMPGTEQ_U, d);
        Test(TT_CMPLT_U, d);
        Test(TT_CMPLTEQ, d);
        Test(TT_CMPGT, d);
        Test(TT_CMPGTEQ, d);
        Test(TT_CMPLT, d);
        Test(TT_FULLMUL, d);
        Test(TT_MUL, d);
    }
}

void CFHE_Test::TestAll()
{
    const int NUM_TEST = 1;
    const int VERBOSITY = 4;
    CFHE_Test *c;
    c = new CFHE_Test(CCPARAM_STD128, AE_GATELOGIC);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->SetRegenerateKeys(false);
    c->StartTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD128_3, AE_OPTIMIZED);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->SetRegenerateKeys(false);
    c->StartTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD192, AE_GATELOGIC);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->SetRegenerateKeys(false);
    c->StartTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD192_3, AE_OPTIMIZED);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->SetRegenerateKeys(false);
    c->StartTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD256, AE_GATELOGIC);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->SetRegenerateKeys(false);
    c->StartTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD256_3, AE_OPTIMIZED);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->SetRegenerateKeys(false);
    c->StartTest();
    delete c;
}

void CFHE_Test::TestAllNoise()
{
    const int NUM_TEST = 10;
    const int VERBOSITY = 2;
    CFHE_Test *c;
    c = new CFHE_Test(CCPARAM_STD128, AE_GATELOGIC);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->StartNoiseTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD128_3, AE_OPTIMIZED);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->StartNoiseTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD192, AE_GATELOGIC);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->StartNoiseTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD192_3, AE_OPTIMIZED);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->StartNoiseTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD256, AE_GATELOGIC);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->StartNoiseTest();
    delete c;
    c = new CFHE_Test(CCPARAM_STD256_3, AE_OPTIMIZED);
    c->SetNumTest(NUM_TEST);
    c->SetVerbosity(VERBOSITY);
    c->StartNoiseTest();
    delete c;
}