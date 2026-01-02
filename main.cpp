#include "CFHE_Test.h"
#include "AEGateLogic.h"
#include <iostream>
using namespace std;

void test_cost_time()
{
    CFHE_Test t(CCPARAM_STD128_3, AE_OPTIMIZED);

    ComputeFHE *cfhe = t.GetBase();
    CFixedPoint c = cfhe->EncryptInt(0, 8);
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());
    for (uint k = 0; k < 256; k += 13)
    {
        size_t n = 0;
        PFixedPoint pt = cfhe->uint2PFixedPoint(k, 8);
        uint cost = ae->Get_PtFullMul_Cost(pt, 8, n);
        uint cost2 = ae->Get_Pt2sCompFullMul_Cost(pt, 8);
        t.StartTimer();
        ae->FullMul(c, pt);
        double tm1 = t.ReadTimer();
        t.StartTimer();
        ae->FullMulFast(c, pt);
        double tm2 = t.ReadTimer();
        cout << "k: " << k << " cost: " << cost << " cost2: " << cost2
             << " time1: " << tm1 << " ms"
             << " time2: " << tm2 << " ms" << endl;
    }
}

void manual_test()
{
    CFHE_Test t(CCPARAM_STD128_3, AE_OPTIMIZED);
    t.SetNumTest(100);
    t.SetVerbosity(4);
    t.SetRegenerateKeys(false);
    t.Test(TT_PFULLMUL_FAST, 8);
}

void calculate_expected_cost()
{
    CFHE_Test t(CCPARAM_STD128_3, AE_OPTIMIZED);

    ComputeFHE *cfhe = t.GetBase();
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());

    uint64_t bs_fullmul = 0;
    uint64_t bs_fullmul_fast = 0;
    uint n = 8;
    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = cfhe->uint2PFixedPoint(k, n);
        size_t ct_n_bits = n;
        size_t out_n_bits = 0;
        uint cost1 = ae->Get_PtFullMul_Cost(pt, ct_n_bits, out_n_bits);
        uint cost2 = ae->Get_Pt2sCompFullMul_Cost(pt, ct_n_bits);
        bs_fullmul += cost1;
        bs_fullmul_fast += (cost1 <= cost2) ? cost1 : cost2;
    }
    float avg_fullmul = (float)bs_fullmul / (1U << n);
    float avg_fullmul_fast = (float)bs_fullmul_fast / (1U << n);
    cout << "Average FullMul CtPt cost for " << n << "-bits : " << avg_fullmul << endl;
    cout << "Average FullMulFast CtPt cost for " << n << "-bits : " << avg_fullmul_fast << endl;
}

int main()
{
    // CFHE_Test::TestAll();
    // CFHE_Test::TestAllNoise();

    // test_cost_time();
    manual_test();
    // calculate_expected_cost();

    return EXIT_SUCCESS;
}
