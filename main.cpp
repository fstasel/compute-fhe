#include "CFHE_Test.h"
#include "AEGateLogic.h"
#include "SimGateLogic.h"
#include "SimTest.h"
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
    // t.Test(TT_MUL, 8);
    t.Test(TT_PMUL, 8);
    t.Test(TT_PMUL_FAST, 8);

    // Fullmul variants
    // t.Test(TT_FULLMUL, 8);
    t.Test(TT_PFULLMUL, 8);
    t.Test(TT_PFULLMUL_FAST, 8);
    t.Test(TT_BOOTHSMUL, 8);

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
    // t.Test(TT_PMUX, 1);
    // t.Test(TT_PPMUX, 1);

    // Adder
    t.Test(TT_PADD, 4);
    t.Test(TT_PADD_NC, 4);
    t.Test(TT_PADDC, 4);
    t.Test(TT_PADDC_NC, 4);
    t.Test(TT_PSUB, 4);
    t.Test(TT_PSUB_NC, 4);
    t.Test(TT_PSUBC, 4);
    t.Test(TT_PSUBC_NC, 4);
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
    ComputeFHE t(CCPARAM_TOY, ae_type);
    AEGateLogic *ae = (AEGateLogic *)(t.GetArithmeticsEngine());
    BaseAESimulator *sim = t.GetSimulator();

    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = t.uint2PFixedPoint(k, n);
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
    ComputeFHE t(CCPARAM_TOY, ae_type);
    AEGateLogic *ae = (AEGateLogic *)(t.GetArithmeticsEngine());
    BaseAESimulator *sim = t.GetSimulator();

    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = t.uint2PFixedPoint(k, n);
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
    ComputeFHE t(CCPARAM_TOY, ae_type);
    AEGateLogic *ae = (AEGateLogic *)(t.GetArithmeticsEngine());
    BaseAESimulator *sim = t.GetSimulator();

    for (uint64_t k = 0; k < ((uint64_t)1U << (uint64_t)n); k++)
    {
        PFixedPoint pt = t.uint2PFixedPoint(k, n);
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
    ComputeFHE t(CCPARAM_TOY, ae_type);
    BaseAESimulator *sim = t.GetSimulator();

    PFixedPoint pt = t.uint2PFixedPoint(14, n);
    CFixedPoint ct(n);
    sim->ResetStats();
    sim->CmpEq(ct, ct);
    cout << "CmpEq cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpEq(ct, pt);
    cout << "CmpEq Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT(ct, ct);
    cout << "CmpGT cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT(pt, ct);
    cout << "CmpGT PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT(ct, pt);
    cout << "CmpGT CtPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT_U(ct, ct);
    cout << "CmpGT_U cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT_U(pt, ct);
    cout << "CmpGT_U PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGT_U(ct, pt);
    cout << "CmpGT_U CtPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT_U(ct, ct);
    cout << "CmpLT_U cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT_U(pt, ct);
    cout << "CmpLT_U PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT_U(ct, pt);
    cout << "CmpLT_U CtPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT(ct, ct);
    cout << "CmpLT cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT(pt, ct);
    cout << "CmpLT PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLT(ct, pt);
    cout << "CmpLT CtPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq(ct, ct);
    cout << "CmpLTEq cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq(pt, ct);
    cout << "CmpLTEq PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq(ct, pt);
    cout << "CmpLTEq CtPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq_U(ct, ct);
    cout << "CmpLTEq_U cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq_U(pt, ct);
    cout << "CmpLTEq_U PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpLTEq_U(ct, pt);
    cout << "CmpLTEq_U CtPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq_U(ct, ct);
    cout << "CmpGTEq_U cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq_U(pt, ct);
    cout << "CmpGTEq_U PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq_U(ct, pt);
    cout << "CmpGTEq_U CtPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq(ct, ct);
    cout << "CmpGTEq cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq(pt, ct);
    cout << "CmpGTEq PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpGTEq(ct, pt);
    cout << "CmpGTEq CtPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpNotEq(ct, ct);
    cout << "CmpNotEq cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->CmpNotEq(pt, ct);
    cout << "CmpNotEq PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Add(ct, ct);
    cout << "Add cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Add(pt, ct);
    cout << "Add Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddC(ct, ct);
    cout << "AddC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddC(pt, ct);
    cout << "AddC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddNC(ct, ct);
    cout << "AddNC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddNC(pt, ct);
    cout << "AddNC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddCNC(ct, ct);
    cout << "AddCNC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->AddCNC(pt, ct);
    cout << "AddCNC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Sub(ct, ct);
    cout << "Sub cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Sub(pt, ct);
    cout << "Sub Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubC(ct, ct);
    cout << "SubC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubC(pt, ct);
    cout << "SubC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubNC(ct, ct);
    cout << "SubNC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubNC(pt, ct);
    cout << "SubNC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubCNC(ct, ct);
    cout << "SubCNC cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->SubCNC(pt, ct);
    cout << "SubCNC Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->FullMul(ct, ct);
    cout << "FullMul cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mul(ct, ct);
    cout << "Mul cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->FullMul(ct, pt);
    cout << "FullMul Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mul(ct, pt);
    cout << "Mul pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->BoothsMul(ct, pt);
    cout << "BoothsMul Pt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(BaseAESimulator::dummy_ct, BaseAESimulator::dummy_ct, BaseAESimulator::dummy_ct);
    cout << "Mux cost : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(BaseAESimulator::dummy_ct, BaseAESimulator::dummy_ct, 1);
    cout << "Mux CtPt cost : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(BaseAESimulator::dummy_ct, 1, BaseAESimulator::dummy_ct);
    cout << "Mux PtCt cost : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    LWEPlaintext dummy1;
    bool dummy2;
    sim->Mux(BaseAESimulator::dummy_ct, 1, 0, BaseAESimulator::dummy_ct, dummy1, dummy2);
    cout << "Mux PtPt cost : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(BaseAESimulator::dummy_ct, ct, ct);
    cout << "Mux cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(BaseAESimulator::dummy_ct, ct, pt);
    cout << "Mux CtPt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
    sim->ResetStats();
    sim->Mux(BaseAESimulator::dummy_ct, pt, ct);
    cout << "Mux PtCt cost for " << n << "-bits : " << endl;
    sim->PrintStats();
    cout << "----------------------------------------" << endl;
}

void test_simulator_manual()
{
    ComputeFHE c1(CCPARAM_STD256, AE_GATELOGIC);
    ComputeFHE c2(CCPARAM_STD256_3, AE_OPTIMIZED);
    // PFixedPoint p = c1.uint2PFixedPoint(78);
    BaseAESimulator *s1 = c1.GetSimulator();
    // s1->FullMul(p, CFixedPoint(8));
    // s1->Mul(CFixedPoint(32), CFixedPoint(32));
    // s1->MulAdd(true);
    s1->SimMul(1);
    s1->PrintStats();
    BaseAESimulator *s2 = c2.GetSimulator();
    // s2->FullMul(p, CFixedPoint(8));
    // s2->Mul(CFixedPoint(32), CFixedPoint(32));
    // s2->MulAdd(true);
    s2->SimMul(1);
    s2->PrintStats();
}

int main()
{
    SimTest::TestAll();

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
    // test_simulator_fullmul_ctpt(4, AE_OPTIMIZED);
    // test_simulator_mul_ctpt(4, AE_GATELOGIC);
    // test_simulator_mul_ctpt(4, AE_OPTIMIZED);
    // test_simulator_booths(4, AE_GATELOGIC);
    // test_simulator_booths(4, AE_OPTIMIZED);
    // test_simulator(4, AE_GATELOGIC);
    // test_simulator(4, AE_OPTIMIZED);
    // test_simulator_manual();

    return EXIT_SUCCESS;
}
