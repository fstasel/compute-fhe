#pragma once

#include "ComputeFHE.h"
#include <iostream>
#include <string>
#include <cstdint>
#include <limits>

using namespace std;

class SimTest
{
public:
    static void TestAll()
    {
        cout << fixed;
        TestSimulator(CCPARAM_STD128, AE_GATELOGIC);
        TestSimulator(CCPARAM_STD128_3, AE_OPTIMIZED);
        TestSimulator(CCPARAM_STD192, AE_GATELOGIC);
        TestSimulator(CCPARAM_STD192_3, AE_OPTIMIZED);
        TestSimulator(CCPARAM_STD256, AE_GATELOGIC);
        TestSimulator(CCPARAM_STD256_3, AE_OPTIMIZED);
    }

    static void TestSimulator(CryptoContextParam p, ArithmeticsEngineType t)
    {
        ComputeFHE cfhe(p, t);
        BaseAESimulator *s = cfhe.GetSimulator();

        // Test primitives
        TestANDOR(s);
        TestXOR(s);
        TestMAJ(s);
        TestXOR3(s);
        TestMA(s);
        TestMAC(s);
        TestMUX(s);
        TestDS(s);

        // Test operators
        TestAdd(s);
        TestNeg(s);
        TestCmp(s);
        TestFullMul(s);
        TestMul(s);
        TestBoothsMul(s);
    }

    template <typename Func, typename... Args>
    static void TestSingle(string tag, Func func, BaseAESimulator *s, Args... args)
    {
        cout << "Test: " << tag << " " << ToString(s->GetBase()->GetCryptoContextParam())
             << " " << ToString(s->GetBase()->GetArithmeticsEngineType()) << " ";
        s->ResetStats();
        func(s, args...);
        s->PrintStats();
    }

    template <typename Func, typename... Args>
    static void TestMulti(string tag, Func func, BaseAESimulator *s, uint d, Args... args)
    {
        cout << "Test: " << tag << " " << ToString(s->GetBase()->GetCryptoContextParam())
             << " " << ToString(s->GetBase()->GetArithmeticsEngineType()) << " ";
        uint64_t bs, t_bs = 0, m_bs = 0;
        long double a_bs;
        int err, m_err = INT32_MIN;
        uint64_t tm, t_tm = 0, m_tm = 0;
        long double a_tm;
        uint64_t n = (uint64_t)1U << (uint64_t)d;
        uint64_t step = (n >> 24) > 0 ? (n >> 24) + 1 : 1;
        uint64_t c = 0;
        for (uint64_t k = 0; k < n; k += step, c++)
        {
            s->ResetStats();
            func(s, s->GetBase()->uint2PFixedPoint(k, d), args...);
            bs = s->GetNumBS();
            err = s->GetLog2Error();
            tm = s->GetEstimatedTime();
            m_bs = (bs > m_bs) ? bs : m_bs;
            t_bs += bs;
            m_err = (err > m_err) ? err : m_err;
            t_tm += tm;
            m_tm = (tm > m_tm) ? tm : m_tm;
        }
        a_bs = (long double)t_bs / c;
        a_tm = (long double)t_tm / c;
        cout << "AverageBS: " << a_bs << " ";
        cout << "AverageTime: " << a_tm << " ";
        cout << "MaxBS: " << m_bs << " ";
        cout << "MaxTime: " << m_tm << " ";
        cout << "MaxError: " << m_err << endl;
    }

    static void TestANDOR(BaseAESimulator *s)
    {
        TestSingle("AND/OR", [](BaseAESimulator *ss)
                   { ss->ANDOR(); }, s);
    }

    static void TestXOR(BaseAESimulator *s)
    {
        TestSingle("XOR", [](BaseAESimulator *ss)
                   { ss->XORXNOR(); }, s);
    }

    static void TestMAJ(BaseAESimulator *s)
    {
        TestSingle("MAJ", [](BaseAESimulator *ss)
                   { ss->MAJ(); }, s);
    }

    static void TestXOR3(BaseAESimulator *s)
    {
        TestSingle("XOR3", [](BaseAESimulator *ss)
                   { ss->XOR3(); }, s);
    }

    static void TestMA(BaseAESimulator *s)
    {
        TestSingle("MA", [](BaseAESimulator *ss)
                   { ss->MulAdd(false); }, s);
    }

    static void TestMAC(BaseAESimulator *s)
    {
        TestSingle("MAC", [](BaseAESimulator *ss)
                   { ss->MulAdd(true); }, s);
    }

    static void TestMUX(BaseAESimulator *s)
    {
        TestSingle("MUX", [](BaseAESimulator *ss)
                   { ss->SimMux(); }, s);
    }

    static void TestDS(BaseAESimulator *s)
    {
        TestSingle("DS", [](BaseAESimulator *ss)
                   { ss->DigitSum(); }, s);
    }

    static void TestAdd(BaseAESimulator *s)
    {
        for (uint d = 4; d <= 64U; d <<= 1)
        {
            TestSingle(string("Add") + to_string(d), [](BaseAESimulator *ss, uint dd)
                       { ss->SimAddNC(dd); }, s, d);
        }
        for (uint d = 4; d <= 32U; d <<= 1)
        {
            TestMulti(string("PAdd") + to_string(d), [](BaseAESimulator *ss, PFixedPoint a)
                      { ss->SimAddNC(a); }, s, d);
        }
    }

    static void TestNeg(BaseAESimulator *s)
    {
        for (uint d = 4; d <= 64U; d <<= 1)
        {
            TestSingle(string("Neg") + to_string(d), [](BaseAESimulator *ss, uint dd)
                       { ss->SimNeg(dd); }, s, d);
        }
    }

    static void TestCmp(BaseAESimulator *s)
    {
        for (uint d = 4; d <= 64U; d <<= 1)
        {
            TestSingle(string("Cmp") + to_string(d), [](BaseAESimulator *ss, uint dd)
                       { ss->SimCmpLTEq_U(dd); }, s, d);
        }
        for (uint d = 4; d <= 32U; d <<= 1)
        {
            TestMulti(string("PCmp") + to_string(d), [](BaseAESimulator *ss, PFixedPoint a)
                      { ss->SimCmpLTEq_U(a); }, s, d);
        }
        for (uint d = 4; d <= 64U; d <<= 1)
        {
            TestSingle(string("CmpEq") + to_string(d), [](BaseAESimulator *ss, uint dd)
                       { ss->SimCmpEq(dd); }, s, d);
        }
        for (uint d = 4; d <= 32U; d <<= 1)
        {
            TestMulti(string("PCmpEq") + to_string(d), [](BaseAESimulator *ss, PFixedPoint a)
                      { ss->SimCmpEq(a); }, s, d);
        }
    }

    static void TestFullMul(BaseAESimulator *s)
    {
        for (uint d = 4; d <= 64U; d <<= 1)
        {
            TestSingle(string("FullMul") + to_string(d), [](BaseAESimulator *ss, uint dd)
                       { ss->SimFullMul(dd); }, s, d);
        }
        for (uint d = 4; d <= 32U; d <<= 1)
        {
            TestMulti(string("PFullMul") + to_string(d), [](BaseAESimulator *ss, PFixedPoint a, uint dd)
                      { ss->SimFullMul(dd, a); }, s, d, d);
        }
        for (uint d = 4; d <= 32U; d <<= 1)
        {
            TestMulti(string("PFullMulFast") + to_string(d), [](BaseAESimulator *ss, PFixedPoint a, uint dd)
                      { ss->SimFullMulFast(dd, a); }, s, d, d);
        }
    }
    static void TestMul(BaseAESimulator *s)
    {
        for (uint d = 4; d <= 64U; d <<= 1)
        {
            TestSingle(string("Mul") + to_string(d), [](BaseAESimulator *ss, uint dd)
                       { ss->SimMul(dd); }, s, d);
        }
        for (uint d = 4; d <= 32U; d <<= 1)
        {
            TestMulti(string("PMul") + to_string(d), [](BaseAESimulator *ss, PFixedPoint a)
                      { ss->SimMul(a); }, s, d);
        }
        for (uint d = 4; d <= 32U; d <<= 1)
        {
            TestMulti(string("PMulFast") + to_string(d), [](BaseAESimulator *ss, PFixedPoint a)
                      { ss->SimMulFast(a); }, s, d);
        }
    }
    static void TestBoothsMul(BaseAESimulator *s)
    {
        for (uint d = 4; d <= 32U; d <<= 1)
        {
            TestMulti(string("PBoothsMul") + to_string(d), [](BaseAESimulator *ss, PFixedPoint a, uint dd)
                      { ss->SimBoothsMul(dd, a); }, s, d, d);
        }
    }
};