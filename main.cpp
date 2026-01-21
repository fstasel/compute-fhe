#include "CFHE_Test.h"
#include "AEGateLogic.h"
#include <iostream>
using namespace std;

void test_cost_time_fullmul()
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

void test_cost_time_mul()
{
    CFHE_Test t(CCPARAM_STD128_3, AE_OPTIMIZED);

    ComputeFHE *cfhe = t.GetBase();
    CFixedPoint c = cfhe->EncryptInt(0, 8);
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());
    for (uint k = 0; k < 256; k += 13)
    {
        PFixedPoint pt = cfhe->uint2PFixedPoint(k, 8);
        uint cost = ae->Get_PtMul_Cost(pt);
        uint cost2 = ae->Get_Pt2sCompMul_Cost(pt);
        t.StartTimer();
        ae->Mul(c, pt);
        double tm1 = t.ReadTimer();
        t.StartTimer();
        ae->MulFast(c, pt);
        double tm2 = t.ReadTimer();
        cout << "k: " << k << " cost: " << cost << " cost2: " << cost2
             << " time1: " << tm1 << " ms"
             << " time2: " << tm2 << " ms" << endl;
    }
}

void manual_test()
{
    CFHE_Test t(CCPARAM_TOY, AE_OPTIMIZED);
    t.SetNumTest(100);
    t.SetVerbosity(4);
    t.SetRegenerateKeys(false);

    // Mul variants
    // t.Test(TT_MUL, 4);
    // t.Test(TT_PMUL, 4);
    // t.Test(TT_PMUL_FAST, 4);

    // Fullmul variants
    // t.Test(TT_FULLMUL, 4);
    // t.Test(TT_PFULLMUL, 4);
    // t.Test(TT_PFULLMUL_FAST, 4);
    // t.Test(TT_BOOTHSMUL, 4);

    // Compares
    // t.Test(TT_CMPEQ, 4);
    // t.Test(TT_PCMPEQ, 4);
    // t.Test(TT_CMPGT, 4);
    // t.Test(TT_PCMPGT, 4);
    // t.Test(TT_CMPGT_U, 4);
    // t.Test(TT_PCMPGT_U, 4);
    // t.Test(TT_CMPGTEQ, 4);
    // t.Test(TT_PCMPGTEQ, 4);
    // t.Test(TT_CMPGTEQ_U, 4);
    // t.Test(TT_PCMPGTEQ_U, 4);
    // t.Test(TT_CMPLT, 4);
    // t.Test(TT_PCMPLT, 4);
    // t.Test(TT_CMPLT_U, 4);
    // t.Test(TT_PCMPLT_U, 4);
    // t.Test(TT_CMPLTEQ, 4);
    // t.Test(TT_PCMPLTEQ, 4);
    // t.Test(TT_CMPLTEQ_U, 4);
    // t.Test(TT_PCMPLTEQ_U, 4);
    // t.Test(TT_CMPNOTEQ, 4);
    // t.Test(TT_PCMPNOTEQ, 4);

    // Invert
    // t.Test(TT_NEG, 4);

    // Multiplexer
    t.Test(TT_MUX, 1);
}

void calculate_expected_cost_fullmul(uint n, ArithmeticsEngineType ae_type)
{
    CFHE_Test t(CCPARAM_TOY, ae_type);

    ComputeFHE *cfhe = t.GetBase();
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());

    uint64_t bs_fullmul = 0;
    uint64_t bs_fullmul_fast = 0;
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

void calculate_expected_cost_mul(uint n, ArithmeticsEngineType ae_type)
{
    CFHE_Test t(CCPARAM_TOY, ae_type);

    ComputeFHE *cfhe = t.GetBase();
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());

    uint64_t bs_mul = 0;
    uint64_t bs_mul_fast = 0;
    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = cfhe->uint2PFixedPoint(k, n);
        uint cost1 = ae->Get_PtMul_Cost(pt);
        uint cost2 = ae->Get_Pt2sCompMul_Cost(pt);
        bs_mul += cost1;
        bs_mul_fast += (cost1 <= cost2) ? cost1 : cost2;
    }
    float avg_mul = (float)bs_mul / (1U << n);
    float avg_mul_fast = (float)bs_mul_fast / (1U << n);
    cout << "Average Mul CtPt cost for " << n << "-bits : " << avg_mul << endl;
    cout << "Average MulFast CtPt cost for " << n << "-bits : " << avg_mul_fast << endl;
}

void calculate_expected_cost_dmul(uint n, ArithmeticsEngineType ae_type)
{
    CFHE_Test t(CCPARAM_TOY, ae_type);

    ComputeFHE *cfhe = t.GetBase();
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());

    uint64_t bs_mul = 0;
    uint64_t bs_mul_fast = 0;
    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = cfhe->uint2PFixedPoint(k, n << 1);
        uint cost1 = ae->Get_PtMul_Cost(pt);
        uint cost2 = ae->Get_Pt2sCompMul_Cost(pt);
        bs_mul += cost1;
        bs_mul_fast += (cost1 <= cost2) ? cost1 : cost2;
    }
    float avg_mul = (float)bs_mul / (1U << n);
    float avg_mul_fast = (float)bs_mul_fast / (1U << n);
    cout << "Average DMul CtPt cost for " << n << "-bits : " << avg_mul << endl;
    cout << "Average DMulFast CtPt cost for " << n << "-bits : " << avg_mul_fast << endl;
}

void calculate_expected_cost_booths(uint n, ArithmeticsEngineType ae_type)
{
    CFHE_Test t(CCPARAM_TOY, ae_type);

    ComputeFHE *cfhe = t.GetBase();
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());

    uint64_t bs_boothsmul = 0;
    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = cfhe->uint2PFixedPoint(k, n);
        size_t ct_n_bits = n;
        bs_boothsmul += ae->Get_BoothsMul_Cost(pt, ct_n_bits);
    }
    float avg_boothsmul = (float)bs_boothsmul / (1U << n);
    cout << "Average BoothsMul CtPt cost for " << n << "-bits : " << avg_boothsmul << endl;
}

int main()
{
    // CFHE_Test::TestAll();
    // CFHE_Test::TestAllNoise();

    // test_cost_time_mul();
    manual_test();
    // calculate_expected_cost_fullmul(4, AE_GATELOGIC);
    // calculate_expected_cost_booths(4, AE_GATELOGIC);
    // calculate_expected_cost_dmul(4, AE_GATELOGIC);
    // calculate_expected_cost_fullmul(8, AE_GATELOGIC);
    // calculate_expected_cost_booths(8, AE_GATELOGIC);
    // calculate_expected_cost_dmul(8, AE_GATELOGIC);
    // calculate_expected_cost_fullmul(16, AE_GATELOGIC);
    // calculate_expected_cost_booths(16, AE_GATELOGIC);
    // calculate_expected_cost_dmul(16, AE_GATELOGIC);
    // calculate_expected_cost_fullmul(4, AE_OPTIMIZED);
    // calculate_expected_cost_booths(4, AE_OPTIMIZED);
    // calculate_expected_cost_dmul(4, AE_OPTIMIZED);
    // calculate_expected_cost_fullmul(8, AE_OPTIMIZED);
    // calculate_expected_cost_booths(8, AE_OPTIMIZED);
    // calculate_expected_cost_dmul(8, AE_OPTIMIZED);
    // calculate_expected_cost_fullmul(16, AE_OPTIMIZED);
    // calculate_expected_cost_booths(16, AE_OPTIMIZED);
    // calculate_expected_cost_dmul(16, AE_OPTIMIZED);
    return EXIT_SUCCESS;
}
