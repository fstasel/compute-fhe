#include "ComputeFHE.h"
#include "AEGateLogic.h"
#include "AEOptimized.h"
#include <iostream>

using namespace std;

void ComputeFHE::createCC()
{
    switch (cc_param)
    {
    case CCPARAM_STD256_LMKCDEY:
        cc.GenerateBinFHEContext(STD256_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD256_3_LMKCDEY:
        cc.GenerateBinFHEContext(STD256_3_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD256:
        cc.GenerateBinFHEContext(STD256);
        break;

    case CCPARAM_STD256_3:
        cc.GenerateBinFHEContext(STD256_3);
        break;

    case CCPARAM_STD192_LMKCDEY:
        cc.GenerateBinFHEContext(STD192_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD192_3_LMKCDEY:
        cc.GenerateBinFHEContext(STD192_3_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD192:
        cc.GenerateBinFHEContext(STD192);
        break;

    case CCPARAM_STD192_3:
        cc.GenerateBinFHEContext(STD192_3);
        break;

    case CCPARAM_STD128_LMKCDEY:
        cc.GenerateBinFHEContext(STD128_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD128_3_LMKCDEY:
        cc.GenerateBinFHEContext(STD128_3_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD128:
        cc.GenerateBinFHEContext(STD128);
        break;

    case CCPARAM_STD128_3:
    default:
        cc.GenerateBinFHEContext(STD128_3);
    }
}

void ComputeFHE::generateKeys()
{
    sk = cc.KeyGen();
    if (verbosity >= 4)
    {
        cout << "Generating the bootstrapping keys..." << endl;
    }
    cc.BTKeyGen(sk);
    if (verbosity >= 4)
    {
        cout << "Completed the key generation." << endl;
    }
}

void ComputeFHE::initRandomGenerator(uint max)
{
    gen = mt19937(rd());
    dis = uniform_int_distribution<uint>(0, max);
}

double ComputeFHE::extractNoise(ConstLWECiphertext &ct)
{
    // OpenFHE Decryption routine
    const auto &mod = ct->GetModulus();
    const auto &a = ct->GetA();
    auto s = sk->GetElement();
    uint32_t n = s.GetLength();
    auto mu = mod.ComputeMu();
    s.SwitchModulus(mod);
    NativeInteger inner(0);
    for (size_t i = 0; i < n; ++i)
    {
        inner += a[i].ModMulFast(s[i], mod, mu);
    }
    inner.ModEq(mod);
    NativeInteger r = ct->GetB();
    r.ModSubFastEq(inner, mod);
    LWEPlaintextModulus p = 4;
    r.ModAddFastEq((mod / (p * 2)), mod);
    LWEPlaintext result = ((NativeInteger(p) * r) / mod).ConvertToInt();
    double error =
        (static_cast<double>(p) * (r.ConvertToDouble() - mod.ConvertToDouble() / (p * 2))) / mod.ConvertToDouble() -
        static_cast<double>(result);
    return error * mod.ConvertToDouble() / static_cast<double>(p);
}

void ComputeFHE::createAE()
{
    switch (ae_type)
    {
    case AE_OPTIMIZED:
        ae = new AEOptimized(this);
        break;

    case AE_GATELOGIC:
    default:
        ae = new AEGateLogic(this);
    }
}

void ComputeFHE::StartTimer()
{
    t0 = timeNow();
}

double ComputeFHE::ReadTimer()
{
    return (timeNow() - t0).count() / 1e6;
}

ComputeFHE::ComputeFHE() : ComputeFHE(CCPARAM_STD128, AE_GATELOGIC)
{
}

ComputeFHE::ComputeFHE(CryptoContextParam param) : ComputeFHE(param, AE_GATELOGIC)
{
}

ComputeFHE::ComputeFHE(ArithmeticsEngineType engine_type) : ComputeFHE(CCPARAM_STD128, engine_type)
{
}

ComputeFHE::~ComputeFHE()
{
    delete ae;
}

ComputeFHE::ComputeFHE(CryptoContextParam param, ArithmeticsEngineType engine_type)
    : cc_param(param), ae_type(engine_type)
{
    createCC();
    generateKeys();
    initRandomGenerator(UINT32_MAX);
    createAE();
}

BinFHEContext &ComputeFHE::GetBinFHEContext()
{
    return cc;
}

CryptoContextParam ComputeFHE::GetCryptoContextParam()
{
    return cc_param;
}

ArithmeticsEngineType ComputeFHE::GetArithmeticsEngineType()
{
    return ae_type;
}

const LWEPrivateKey &ComputeFHE::GetLWEPrivateKey()
{
    return sk;
}

uint ComputeFHE::GetNumTest()
{
    return num_test;
}

void ComputeFHE::SetNumTest(uint n)
{
    num_test = n;
}

uint ComputeFHE::GetVerbosity()
{
    return verbosity;
}

void ComputeFHE::SetVerbosity(uint v)
{
    verbosity = (v <= 4) ? v : 4;
}

bool ComputeFHE::GetTestFresh()
{
    return test_fresh;
}

void ComputeFHE::SetTestFresh(bool val)
{
    test_fresh = val;
}

FixedPoint ComputeFHE::EncryptInt(uint pt, size_t n_digits, bool fresh)
{
    FixedPoint out(n_digits);
    for (size_t i = 0; i < n_digits; i++)
    {
        out[i] = cc.Encrypt(sk, pt % 2, FRESH);
        pt /= 2;
        if (!fresh)
        {
            out[i] = cc.Bootstrap(out[i]);
        }
    }
    return out;
}

uint ComputeFHE::DecryptInt(const FixedPoint &ct, size_t n_digits)
{
    uint32_t out = 0;
    LWEPlaintext result;
    n_digits = (n_digits == 0) ? ct.size() : n_digits;
    for (size_t i = 0; i < n_digits; i++)
    {
        cc.Decrypt(sk, ct[i], &result);
        out += result * (1UL << i);
    }
    return out;
}

LWECiphertext ComputeFHE::EncryptBool(uint pt, bool fresh)
{
    LWECiphertext out = cc.Encrypt(sk, pt == 0 ? 0 : 1, FRESH);
    if (!fresh)
    {
        out = cc.Bootstrap(out);
    }
    return out;
}

uint ComputeFHE::DecryptBool(ConstLWECiphertext &ct)
{
    LWEPlaintext result;
    cc.Decrypt(sk, ct, &result);
    return result;
}

void ComputeFHE::PrintCryptoContextParams()
{
    cout << "cc Q=" << cc.GetParams()->GetLWEParams()->GetQ() << endl
         << "cc q=" << cc.GetParams()->GetLWEParams()->Getq() << endl
         << "cc N=" << cc.GetParams()->GetLWEParams()->GetN() << endl
         << "cc n=" << cc.GetParams()->GetLWEParams()->Getn() << endl
         << "cc BaseKS=" << cc.GetParams()->GetLWEParams()->GetBaseKS() << endl
         << "cc beta=" << cc.GetBeta() << endl
         << "cc max pt space=" << cc.GetMaxPlaintextSpace() << endl;
}

void ComputeFHE::PrintLWECiphertextParams(ConstLWECiphertext &ct)
{
    cout << "ct len=" << ct->GetLength() << endl
         << "ct mod=" << ct->GetModulus() << endl
         << "ct pt mod=" << ct->GetptModulus() << endl
         << "ct a=" << ct->GetA() << endl
         << "ct b=" << ct->GetB() << endl;
}

uint ComputeFHE::CreateRandomNumber()
{
    return dis(gen);
}

void ComputeFHE::StartTest(TestType tt, size_t n_digits)
{
    cout << "cc_param: " << ToString(cc_param)
         << " ae_type: " << ToString(ae_type)
         << " test_type: " << ToString(tt)
         << " trials: " << num_test
         << " n_digits: " << n_digits << endl;

    initRandomGenerator((1UL << n_digits) - 1);
    uint n_error = 0;
    double t_time = 0, avg_t = 0, err_rate = 0;
    TestReport report;
    for (uint trial = 0; trial < num_test; trial++)
    {
        cc.ClearBTKeys();
        generateKeys();
        //
        switch (tt)
        {
        case TT_ENCRYPT_DECRYPT:
            report = TestEncryptDecrypt(n_digits);
            break;

        case TT_HA:
            report = ae->TestHalfAdder();
            break;

        case TT_FA:
            report = ae->TestFullAdder();
            break;

        case TT_XOR3:
            report = ae->TestXOR3();
            break;

        case TT_MULADD:
            report = ae->TestMulAdd();
            break;

        case TT_ADD:
            report = ae->TestAdd(n_digits);
            break;

        case TT_ADDC:
            report = ae->TestAddC(n_digits);
            break;

        case TT_ADD_NC:
            report = ae->TestAddNC(n_digits);
            break;

        case TT_SUB:
            report = ae->TestSub(n_digits);
            break;

        case TT_SUBC:
            report = ae->TestSubC(n_digits);
            break;

        case TT_SUB_NC:
            report = ae->TestSubNC(n_digits);
            break;

        case TT_NEG:
            report = ae->TestNeg(n_digits);
            break;

        case TT_CMPNOTEQ:
            report = ae->TestCmpNotEq(n_digits);
            break;

        case TT_CMPEQ:
            report = ae->TestCmpEq(n_digits);
            break;

        case TT_CMPLTEQ_U:
            report = ae->TestCmpLTEq_U(n_digits);
            break;

        case TT_CMPGT_U:
            report = ae->TestCmpGT_U(n_digits);
            break;

        case TT_CMPGTEQ_U:
            report = ae->TestCmpGTEq_U(n_digits);
            break;

        case TT_CMPLT_U:
            report = ae->TestCmpLT_U(n_digits);
            break;

        case TT_CMPLTEQ:
            report = ae->TestCmpLTEq(n_digits);
            break;

        case TT_CMPGT:
            report = ae->TestCmpGT(n_digits);
            break;

        case TT_CMPGTEQ:
            report = ae->TestCmpGTEq(n_digits);
            break;

        case TT_CMPLT:
            report = ae->TestCmpLT(n_digits);
            break;

        case TT_FULLMUL:
            report = ae->TestFullMul(n_digits);
            break;

        case TT_MUL:
            report = ae->TestMul(n_digits);
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

TestReport ComputeFHE::TestEncryptDecrypt(size_t n_digits)
{
    TestReport report;
    uint n = CreateRandomNumber();
    StartTimer();
    FixedPoint ct = EncryptInt(n, n_digits, test_fresh);
    uint result = DecryptInt(ct);
    report.delta_t = ReadTimer();
    report.test_result = (n == result) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n, result);
    return report;
}

void ComputeFHE::PrintTestReport(TestReport report, int64_t n, int64_t result)
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

void ComputeFHE::PrintTestReport(TestReport report, int64_t n, int64_t result, int64_t expected)
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

void ComputeFHE::PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t result, int64_t expected)
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

void ComputeFHE::PrintTestReport(TestReport report, int64_t n1, int64_t n2, int64_t n3, int64_t result, int64_t expected)
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

void ComputeFHE::StartNoiseTest()
{
    cout << "cc_param: " << ToString(cc_param)
         << " ae_type: " << ToString(ae_type)
         << " test_type: NOISE"
         << " trials: " << num_test << endl;

    double sum_fresh = 0, sum_bs = 0, noise, noise_bs;
    double delta_t = 0, t_time = 0, avg_t = 0;

    for (uint trial = 1; trial <= num_test; trial++)
    {
        cc.ClearBTKeys();
        generateKeys();
        //
        LWECiphertext ct = cc.Encrypt(sk, CreateRandomNumber() % 2, FRESH);
        //
        StartTimer();
        LWECiphertext ct_bs = cc.Bootstrap(ct);
        delta_t = ReadTimer();
        //
        noise = extractNoise(ct);
        noise_bs = extractNoise(ct_bs);
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

void ComputeFHE::TestAll()
{
    ComputeFHE *c;
    c = new ComputeFHE(CCPARAM_STD128, AE_GATELOGIC);
    Test(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD128_3, AE_OPTIMIZED);
    Test(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD192, AE_GATELOGIC);
    Test(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD192_3, AE_OPTIMIZED);
    Test(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD256, AE_GATELOGIC);
    Test(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD256_3, AE_OPTIMIZED);
    Test(*c);
    delete c;
}

void ComputeFHE::TestAllNoise()
{
    ComputeFHE *c;
    c = new ComputeFHE(CCPARAM_STD128, AE_GATELOGIC);
    TestNoise(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD128_3, AE_OPTIMIZED);
    TestNoise(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD192, AE_GATELOGIC);
    TestNoise(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD192_3, AE_OPTIMIZED);
    TestNoise(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD256, AE_GATELOGIC);
    TestNoise(*c);
    delete c;
    c = new ComputeFHE(CCPARAM_STD256_3, AE_OPTIMIZED);
    TestNoise(*c);
    delete c;
}

void ComputeFHE::Test(ComputeFHE &c)
{
    c.SetNumTest(30);
    c.SetVerbosity(2);
    // c.StartTest(TT_ENCRYPT_DECRYPT);
    c.StartTest(TT_HA, 1);
    c.StartTest(TT_FA, 1);
    c.StartTest(TT_XOR3, 1);
    c.StartTest(TT_MULADD, 1);
    for (uint d = 2; d <= 32U; d <<= 1)
    {
        c.StartTest(TT_ADD, d);
        c.StartTest(TT_ADDC, d);
        c.StartTest(TT_ADD_NC, d);
        c.StartTest(TT_SUB, d);
        c.StartTest(TT_SUBC, d);
        c.StartTest(TT_SUB_NC, d);
        c.StartTest(TT_NEG, d);
        c.StartTest(TT_CMPNOTEQ, d);
        c.StartTest(TT_CMPEQ, d);
        c.StartTest(TT_CMPLTEQ_U, d);
        c.StartTest(TT_CMPGT_U, d);
        c.StartTest(TT_CMPGTEQ_U, d);
        c.StartTest(TT_CMPLT_U, d);
        c.StartTest(TT_CMPLTEQ, d);
        c.StartTest(TT_CMPGT, d);
        c.StartTest(TT_CMPGTEQ, d);
        c.StartTest(TT_CMPLT, d);
        c.StartTest(TT_FULLMUL, d);
        c.StartTest(TT_MUL, d);
    }
}

void ComputeFHE::TestNoise(ComputeFHE &c)
{
    c.SetNumTest(10000);
    c.SetVerbosity(2);
    c.StartNoiseTest();
}
