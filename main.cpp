#include "CFHE_Test.h"
#include "AEGateLogic.h"
#include "SimGateLogic.h"
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
    CFHE_Test t(CCPARAM_TOY, AE_GATELOGIC);
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
    // t.Test(TT_MUX, 1);
    t.Test(TT_PMUX, 1);
    t.Test(TT_PPMUX, 1);
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

void test_simulator_fullmul_ctpt(uint n, ArithmeticsEngineType ae_type)
{
    CFHE_Test t(CCPARAM_TOY, ae_type);
    ComputeFHE *cfhe = t.GetBase();
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());
    SimGateLogic *sim = (SimGateLogic *)(cfhe->GetSimulator());
    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = cfhe->uint2PFixedPoint(k, n);
        size_t ct_n_bits = n;
        size_t out_n_bits = 0;
        uint cost1 = ae->Get_PtFullMul_Cost(pt, ct_n_bits, out_n_bits);
        uint cost2 = ae->Get_Pt2sCompFullMul_Cost(pt, ct_n_bits);
        uint bs_fullmul = cost1;
        uint bs_fullmul_fast = (cost1 <= cost2) ? cost1 : cost2;

        cout << "k: " << k << endl;
        cout << "FullMul CtPt cost: " << bs_fullmul << endl;
        sim->ResetStats();
        sim->FullMul_CtPt_FixedPoint(n, pt);
        sim->PrintStats();
        cout << "FullMulFast CtPt cost: " << bs_fullmul_fast << endl;
        sim->ResetStats();
        sim->FullMulFast_CtPt_FixedPoint(n, pt);
        sim->PrintStats();
        cout << "----------------------------------------" << endl;
    }
}

void test_simulator_mul_ctpt(uint n, ArithmeticsEngineType ae_type)
{
    CFHE_Test t(CCPARAM_TOY, ae_type);
    ComputeFHE *cfhe = t.GetBase();
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());
    SimGateLogic *sim = (SimGateLogic *)(cfhe->GetSimulator());
    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = cfhe->uint2PFixedPoint(k, n);
        uint cost1 = ae->Get_PtMul_Cost(pt);
        uint cost2 = ae->Get_Pt2sCompMul_Cost(pt);
        uint bs_mul = cost1;
        uint bs_mul_fast = (cost1 <= cost2) ? cost1 : cost2;

        cout << "k: " << k << endl;
        cout << "Mul CtPt cost: " << bs_mul << endl;
        sim->ResetStats();
        sim->Mul_CtPt_FixedPoint(pt);
        sim->PrintStats();
        cout << "MulFast CtPt cost: " << bs_mul_fast << endl;
        sim->ResetStats();
        sim->MulFast_CtPt_FixedPoint(pt);
        sim->PrintStats();
        cout << "----------------------------------------" << endl;
    }
}

void test_simulator_booths(uint n, ArithmeticsEngineType ae_type)
{
    CFHE_Test t(CCPARAM_TOY, ae_type);
    ComputeFHE *cfhe = t.GetBase();
    AEGateLogic *ae = (AEGateLogic *)(cfhe->GetArithmeticsEngine());
    SimGateLogic *sim = (SimGateLogic *)(cfhe->GetSimulator());
    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = cfhe->uint2PFixedPoint(k, n);
        size_t ct_n_bits = n;
        uint bs_boothsmul = ae->Get_BoothsMul_Cost(pt, ct_n_bits);

        cout << "k: " << k << endl;
        cout << "BoothsMul cost: " << bs_boothsmul << endl;
        sim->ResetStats();
        sim->BoothsMul_CtPt_FixedPoint(ct_n_bits, pt);
        sim->PrintStats();
        cout << "----------------------------------------" << endl;
    }
}

void test_simulator(uint n, ArithmeticsEngineType ae_type)
{
    CFHE_Test t(CCPARAM_TOY, ae_type);
    ComputeFHE *cfhe = t.GetBase();
    SimGateLogic *sim = (SimGateLogic *)(cfhe->GetSimulator());
    sim->ResetStats();
    sim->CmpEq(n);
    cout << "CmpEq cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpEq(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpEq Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT(n);
    cout << "CmpGT cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpGT Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT(0, cfhe->uint2PFixedPoint(14, n));
    cout << "CmpGT CPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT_U(n);
    cout << "CmpGT_U cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT_U(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpGT_U Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT_U(0, cfhe->uint2PFixedPoint(14, n));
    cout << "CmpGT_U CPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT_U(n);
    cout << "CmpLT_U cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT_U(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpLT_U Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT_U(0, cfhe->uint2PFixedPoint(14, n));
    cout << "CmpLT_U CPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT(n);
    cout << "CmpLT cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpLT Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT(0, cfhe->uint2PFixedPoint(14, n));
    cout << "CmpLT CPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq(n);
    cout << "CmpLTEq cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpLTEq Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq(0, cfhe->uint2PFixedPoint(14, n));
    cout << "CmpLTEq CPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq_U(n);
    cout << "CmpLTEq_U cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq_U(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpLTEq_U Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq_U(0, cfhe->uint2PFixedPoint(14, n));
    cout << "CmpLTEq_U CPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq_U(n);
    cout << "CmpGTEq_U cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq_U(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpGTEq_U Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq_U(0, cfhe->uint2PFixedPoint(14, n));
    cout << "CmpGTEq_U CPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq(n);
    cout << "CmpGTEq cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpGTEq Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq(0, cfhe->uint2PFixedPoint(14, n));
    cout << "CmpGTEq CPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpNotEq(n);
    cout << "CmpNotEq cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpNotEq(cfhe->uint2PFixedPoint(14, n));
    cout << "CmpNotEq Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Add(n);
    cout << "Add cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Add(cfhe->uint2PFixedPoint(14, n));
    cout << "Add Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddC(n);
    cout << "AddC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddC(cfhe->uint2PFixedPoint(14, n));
    cout << "AddC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddNC(n);
    cout << "AddNC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddNC(cfhe->uint2PFixedPoint(14, n));
    cout << "AddNC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddCNC(n);
    cout << "AddCNC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddCNC(cfhe->uint2PFixedPoint(14, n));
    cout << "AddCNC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Sub(n);
    cout << "Sub cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Sub(cfhe->uint2PFixedPoint(14, n));
    cout << "Sub Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubC(n);
    cout << "SubC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubC(cfhe->uint2PFixedPoint(14, n));
    cout << "SubC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubNC(n);
    cout << "SubNC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubNC(cfhe->uint2PFixedPoint(14, n));
    cout << "SubNC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubCNC(n);
    cout << "SubCNC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubCNC(cfhe->uint2PFixedPoint(14, n));
    cout << "SubCNC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux();
    cout << "Mux cost : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(LWEPlaintext(1));
    cout << "Mux Pt cost : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    LWEPlaintext dummy1;
    bool dummy2;
    sim->Mux(LWEPlaintext(1), LWEPlaintext(0), dummy1, dummy2);
    cout << "Mux PtPt cost : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(size_t(n));
    cout << "Mux cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(cfhe->uint2PFixedPoint(14, n));
    cout << "Mux Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(0, cfhe->uint2PFixedPoint(14, n));
    cout << "Mux CPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
}

int main()
{
    // CFHE_Test::TestAll();
    // CFHE_Test::TestAllNoise();

    // test_cost_time_mul();
    // manual_test();
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

    // test_simulator_fullmul_ctpt(4, AE_GATELOGIC);
    // test_simulator_mul_ctpt(4, AE_GATELOGIC);
    // test_simulator_booths(4, AE_GATELOGIC);
    test_simulator(4, AE_GATELOGIC);

    return EXIT_SUCCESS;
}
