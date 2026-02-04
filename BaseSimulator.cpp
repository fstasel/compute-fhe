#include "BaseSimulator.h"
#include "BaseArithmeticsEngine.h"

#include <iostream>
using namespace std;

BaseSimulator::BaseSimulator(ComputeFHE *cfhe) : cfhe_base(cfhe)
{
    ResetCarry();
    ResetStats();
}

BaseSimulator::~BaseSimulator()
{
}

LWEPlaintext BaseSimulator::GetCarryPT()
{
    return carry_pt;
}

void BaseSimulator::SetCarry(LWEPlaintext value)
{
    carry_pt = value;
    is_lastcarry_ct = false;
}

void BaseSimulator::SetCarry()
{
    carry_pt = 1;
    is_lastcarry_ct = false;
}

void BaseSimulator::ResetCarry()
{
    carry_pt = 0;
    is_lastcarry_ct = false;
}

bool BaseSimulator::isLastCarryCT()
{
    return is_lastcarry_ct;
}

void BaseSimulator::SetIsLastCarryCT(bool val)
{
    is_lastcarry_ct = val;
}

void BaseSimulator::PrintStats()
{
    cout << "Number of BS: " << num_bs << endl;
    cout << "Number of NOT: " << num_not << endl;
    cout << "Number of AND/OR: " << num_andor << endl;
    cout << "Number of XOR/XNOR: " << num_xorxnor << endl;
    cout << "Number of XOR3: " << num_xor3 << endl;
    cout << "Number of MAJ: " << num_maj << endl;
    cout << "Number of MA: " << num_ma << endl;
    cout << "Number of MAC: " << num_mac << endl;
    cout << "Number of DS: " << num_ds << endl;
}

void BaseSimulator::ResetStats()
{
    num_bs = 0;
    num_not = 0;
    num_andor = 0;
    num_xorxnor = 0;
    num_xor3 = 0;
    num_maj = 0;
    num_ma = 0;
    num_mac = 0;
    num_ds = 0;
}

size_t BaseSimulator::Add(const size_t n_bits)
{
    return Add_CtCt_FixedPoint(n_bits, false, true);
}

size_t BaseSimulator::AddC(const size_t n_bits)
{
    return Add_CtCt_FixedPoint(n_bits, true, true);
}

size_t BaseSimulator::AddNC(const size_t n_bits)
{
    return Add_CtCt_FixedPoint(n_bits, false, false);
}

size_t BaseSimulator::AddCNC(const size_t n_bits)
{
    return Add_CtCt_FixedPoint(n_bits, true, false);
}

size_t BaseSimulator::Sub(const size_t n_bits)
{
    return Sub_CtCt_FixedPoint(n_bits, false, true);
}

size_t BaseSimulator::SubC(const size_t n_bits)
{
    return Sub_CtCt_FixedPoint(n_bits, true, true);
}

size_t BaseSimulator::SubNC(const size_t n_bits)
{
    return Sub_CtCt_FixedPoint(n_bits, false, false);
}

size_t BaseSimulator::SubCNC(const size_t n_bits)
{
    return Sub_CtCt_FixedPoint(n_bits, true, false);
}

size_t BaseSimulator::Add(const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, false, true);
}

size_t BaseSimulator::AddC(const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, true, true);
}

size_t BaseSimulator::AddNC(const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, false, false);
}

size_t BaseSimulator::AddCNC(const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, true, false);
}

size_t BaseSimulator::Sub(const int a, const PFixedPoint &b)
{
    return Add(Neg(b));
}

size_t BaseSimulator::Sub(const PFixedPoint &a)
{
    return Sub_PtCt_FixedPoint(a, false, true);
}

size_t BaseSimulator::SubC(const int a, const PFixedPoint &b)
{
    return AddC(Not(b));
}

size_t BaseSimulator::SubC(const PFixedPoint &a)
{
    return Sub_PtCt_FixedPoint(a, true, true);
}

size_t BaseSimulator::SubNC(const int a, const PFixedPoint &b)
{
    return AddNC(Neg(b));
}

size_t BaseSimulator::SubNC(const PFixedPoint &a)
{
    return Sub_PtCt_FixedPoint(a, false, false);
}

size_t BaseSimulator::SubCNC(const int a, const PFixedPoint &b)
{
    return AddCNC(Not(b));
}

size_t BaseSimulator::SubCNC(const PFixedPoint &a)
{
    return Sub_PtCt_FixedPoint(a, true, false);
}

void BaseSimulator::CmpNotEq(const size_t n_bits)
{
    return CmpNotEq_CtCt_FixedPoint(n_bits);
}

void BaseSimulator::CmpNotEq(const PFixedPoint &b)
{
    return CmpNotEq_CtPt_FixedPoint(b);
}

void BaseSimulator::CmpEq(const size_t n_bits)
{
    return CmpEq_CtCt_FixedPoint(n_bits);
}

void BaseSimulator::CmpEq(const PFixedPoint &b)
{
    return CmpEq_CtPt_FixedPoint(b);
}

void BaseSimulator::CmpLTEq_U(const size_t n_bits)
{
    return CmpLTEq_U_CtCt_FixedPoint(n_bits);
}

void BaseSimulator::CmpLTEq_U(const int a, const PFixedPoint &b)
{
    return CmpLTEq_U_CtPt_FixedPoint(b);
}

void BaseSimulator::CmpLTEq_U(const PFixedPoint &a)
{
    return CmpGTEq_U(0, a);
}

void BaseSimulator::CmpGT_U(const size_t n_bits)
{
    return CmpGT_U_CtCt_FixedPoint(n_bits);
}

void BaseSimulator::CmpGT_U(const int a, const PFixedPoint &b)
{
    return CmpGT_U_CtPt_FixedPoint(b);
}

void BaseSimulator::CmpGT_U(const PFixedPoint &a)
{
    return CmpLT_U(0, a);
}

void BaseSimulator::CmpGTEq_U(const size_t n_bits)
{
    return CmpLTEq_U_CtCt_FixedPoint(n_bits);
}

void BaseSimulator::CmpGTEq_U(const int a, const PFixedPoint &b)
{
    Not(b.size());
    return CmpLTEq_U_CtPt_FixedPoint(Not(b));
}

void BaseSimulator::CmpGTEq_U(const PFixedPoint &a)
{
    return CmpLTEq_U_CtPt_FixedPoint(a);
}

void BaseSimulator::CmpLT_U(const size_t n_bits)
{
    return CmpGT_U_CtCt_FixedPoint(n_bits);
}

void BaseSimulator::CmpLT_U(const int a, const PFixedPoint &b)
{
    Not(b.size());
    return CmpGT_U_CtPt_FixedPoint(Not(b));
}

void BaseSimulator::CmpLT_U(const PFixedPoint &a)
{
    return CmpGT_U_CtPt_FixedPoint(a);
}

void BaseSimulator::CmpLTEq(const size_t n_bits)
{
    ToggleMSB(n_bits);
    ToggleMSB(n_bits);
    return CmpLTEq_U(n_bits);
}

void BaseSimulator::CmpLTEq(const int a, const PFixedPoint &b)
{
    ToggleMSB(b.size());
    return CmpLTEq_U(a, ToggleMSB(b));
}

void BaseSimulator::CmpLTEq(const PFixedPoint &a)
{
    ToggleMSB(a.size());
    return CmpLTEq_U(ToggleMSB(a));
}

void BaseSimulator::CmpGT(const size_t n_bits)
{
    ToggleMSB(n_bits);
    ToggleMSB(n_bits);
    return CmpGT_U(n_bits);
}

void BaseSimulator::CmpGT(const int a, const PFixedPoint &b)
{
    ToggleMSB(b.size());
    return CmpGT_U(a, ToggleMSB(b));
}

void BaseSimulator::CmpGT(const PFixedPoint &a)
{
    ToggleMSB(a.size());
    return CmpGT_U(ToggleMSB(a));
}

void BaseSimulator::CmpGTEq(const size_t n_bits)
{
    ToggleMSB(n_bits);
    ToggleMSB(n_bits);
    return CmpGTEq_U(n_bits);
}

void BaseSimulator::CmpGTEq(const int a, const PFixedPoint &b)
{
    ToggleMSB(b.size());
    return CmpGTEq_U(a, ToggleMSB(b));
}

void BaseSimulator::CmpGTEq(const PFixedPoint &a)
{
    ToggleMSB(a.size());
    return CmpGTEq_U(ToggleMSB(a));
}

void BaseSimulator::CmpLT(const size_t n_bits)
{
    ToggleMSB(n_bits);
    ToggleMSB(n_bits);
    return CmpLT_U(n_bits);
}

void BaseSimulator::CmpLT(const int a, const PFixedPoint &b)
{
    ToggleMSB(b.size());
    return CmpLT_U(a, ToggleMSB(b));
}

void BaseSimulator::CmpLT(const PFixedPoint &a)
{
    ToggleMSB(a.size());
    return CmpLT_U(ToggleMSB(a));
}

size_t BaseSimulator::ToggleMSB(const size_t n_bits)
{
    return n_bits;
}

PFixedPoint BaseSimulator::ToggleMSB(const PFixedPoint &a)
{
    return cfhe_base->GetArithmeticsEngine()->ToggleMSB(a);
}

void BaseSimulator::PXOR(const LWEPlaintext &b)
{
    if (b == 0)
    {
        return;
    }
    num_not++;
}

void BaseSimulator::PXNOR(const LWEPlaintext &b)
{
    PXOR(1 - b);
}

size_t BaseSimulator::Neg(const size_t n_bits)
{
    return Neg_Ct_FixedPoint(n_bits);
}

PFixedPoint BaseSimulator::Neg(const PFixedPoint &a)
{
    return cfhe_base->GetArithmeticsEngine()->Neg(a);
}

size_t BaseSimulator::Not(const size_t n_bits)
{
    num_not += n_bits;
    return n_bits;
}

PFixedPoint BaseSimulator::Not(const PFixedPoint &a)
{
    return cfhe_base->GetArithmeticsEngine()->Not(a);
}

size_t BaseSimulator::FullMul(const size_t n_bits)
{
    return FullMul_CtCt_FixedPoint(n_bits);
}

size_t BaseSimulator::FullMul(const size_t n_bits, const PFixedPoint &b)
{
    return FullMul_CtPt_FixedPoint(n_bits, b);
}

size_t BaseSimulator::FullMulFast(const size_t n_bits, const PFixedPoint &b)
{
    return FullMulFast_CtPt_FixedPoint(n_bits, b);
}

size_t BaseSimulator::BoothsMul(const size_t n_bits, const PFixedPoint &b)
{
    return BoothsMul_CtPt_FixedPoint(n_bits, b);
}

size_t BaseSimulator::Mul(const size_t n_bits)
{
    return Mul_CtCt_FixedPoint(n_bits);
}

size_t BaseSimulator::Mul(const PFixedPoint &b)
{
    return Mul_CtPt_FixedPoint(b);
}

size_t BaseSimulator::MulFast(const PFixedPoint &b)
{
    return MulFast_CtPt_FixedPoint(b);
}

void BaseSimulator::Mux()
{
    Mux_CCC();
}

void BaseSimulator::Mux(LWEPlaintext b)
{
    Mux_CCP(b);
}

void BaseSimulator::Mux(int s, LWEPlaintext a)
{
    num_not++;
    Mux_CCP(a);
}

void BaseSimulator::Mux(LWEPlaintext a, LWEPlaintext b, LWEPlaintext &out_pt, bool &is_out_ct)
{
    Mux_CPP(a, b, out_pt, is_out_ct);
}

size_t BaseSimulator::Mux(const size_t n_bits)
{
    for (size_t i = 0; i < n_bits; i++)
    {
        Mux();
    }
    return n_bits;
}

size_t BaseSimulator::Mux(const PFixedPoint b)
{
    for (size_t i = 0; i < b.size(); i++)
    {
        Mux(b);
    }
    return b.size();
}

size_t BaseSimulator::Mux(int s, const PFixedPoint a)
{
    for (size_t i = 0; i < a.size(); i++)
    {
        Mux(s, a);
    }
    return a.size();
}
