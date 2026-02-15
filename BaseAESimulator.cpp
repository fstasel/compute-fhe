#include "BaseAESimulator.h"

#include <iostream>
#include <cmath>
using namespace std;

LWECiphertext BaseAESimulator::dummy_ct;
CFixedPoint BaseAESimulator::dummy_cfixedpoint;

BaseAESimulator::BaseAESimulator(ComputeFHE *cfhe) : BaseArithmeticsEngine(cfhe)
{
    ResetStats();
    SimConstants::initSimConstants(bs_time, bs_stdev);
    init_error();
}

void BaseAESimulator::SetCarry()
{
    carry_pt = 1;
    is_lastcarry_ct = false;
}

void BaseAESimulator::ResetCarry()
{
    carry_pt = 0;
    is_lastcarry_ct = false;
}

void BaseAESimulator::PrintStats()
{
    cout << "BS: " << num_bs << " ";
    cout << "NOT: " << num_not << " ";
    cout << "AND/OR: " << num_andor << " ";
    cout << "XOR/XNOR: " << num_xorxnor << " ";
    cout << "XOR3: " << num_xor3 << " ";
    cout << "MAJ: " << num_maj << " ";
    cout << "MA: " << num_ma << " ";
    cout << "MAC: " << num_mac << " ";
    cout << "DS: " << num_ds << " ";
    cout << "MUX: " << num_mux << " ";
    cout << "EstimatedTime: " << GetEstimatedTime() << " ";
    cout << "Log2Error: " << GetLog2Error() << endl;
}

void BaseAESimulator::ResetStats()
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
    num_mux = 0;
}

int BaseAESimulator::GetLog2Error()
{
    long double e = 0;
    uint i;
    for (i = 0; i < num_andor; i++)
    {
        e += error_andor - error_andor * e;
    }
    for (i = 0; i < num_xorxnor; i++)
    {
        e += error_xorxnor - error_xorxnor * e;
    }
    for (i = 0; i < num_xor3; i++)
    {
        e += error_xor3 - error_xor3 * e;
    }
    for (i = 0; i < num_maj; i++)
    {
        e += error_maj - error_maj * e;
    }
    for (i = 0; i < num_ma; i++)
    {
        e += error_ma - error_ma * e;
    }
    for (i = 0; i < num_mac; i++)
    {
        e += error_mac - error_mac * e;
    }
    for (i = 0; i < num_ds; i++)
    {
        e += error_ds - error_ds * e;
    }
    for (i = 0; i < num_mux; i++)
    {
        e += error_mux - error_mux * e;
    }
    return (int)round(log2l(e));
}

uint BaseAESimulator::GetEstimatedTime()
{
    return num_bs * bs_time[cfhe_base->GetCryptoContextParam()];
}

uint BaseAESimulator::GetNumBS()
{
    return num_bs;
}

void BaseAESimulator::HalfAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, LWECiphertext &sum, LWECiphertext &carry_out)
{
    HalfAdder();
}

void BaseAESimulator::HalfAdder(ConstLWECiphertext &a, const LWEPlaintext &b, LWECiphertext &sum, LWECiphertext &carry_out_ct, LWEPlaintext &carry_out_pt, bool &is_carry_ct)
{
    HalfAdder(b, carry_out_pt, is_carry_ct);
}

void BaseAESimulator::HalfSubtractor(ConstLWECiphertext &a, ConstLWECiphertext &b, LWECiphertext &sum, LWECiphertext &carry_out)
{
    HalfSubtractor();
}

void BaseAESimulator::HalfSubtractor(const LWEPlaintext &a, ConstLWECiphertext &b, LWECiphertext &sum, LWECiphertext &carry_out_ct, LWEPlaintext &carry_out_pt, bool &is_carry_ct)
{
    HalfSubtractor(a, carry_out_pt, is_carry_ct);
}

void BaseAESimulator::FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c, LWECiphertext &sum, LWECiphertext &carry_out)
{
    FullAdder();
}

void BaseAESimulator::FullAdder(ConstLWECiphertext &a, const LWEPlaintext &b, const LWEPlaintext &c, LWECiphertext &sum, LWECiphertext &carry_out_ct, LWEPlaintext &carry_out_pt, bool &is_carry_ct)
{
    FullAdder(b, c, carry_out_pt, is_carry_ct);
}

void BaseAESimulator::FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, const LWEPlaintext &c, LWECiphertext &sum, LWECiphertext &carry_out)
{
    FullAdder(c);
}

LWECiphertext BaseAESimulator::XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c)
{
    XOR3();
    return dummy_ct;
}

LWECiphertext BaseAESimulator::MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b, LWECiphertext *carry_out)
{
    MulAdd(carry_out);
    return dummy_ct;
}

LWECiphertext BaseAESimulator::DigitSum(ConstLWECiphertext &e1, ConstLWECiphertext &e0, ConstLWECiphertext &s0)
{
    DigitSum();
    return dummy_ct;
}

CFixedPoint BaseAESimulator::Add_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b, const bool &carry_in, const bool &carry_out)
{
    dummy_cfixedpoint.resize(Add_CtCt_FixedPoint(a.size(), carry_in, carry_out));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::Sub_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b, const bool &carry_in, const bool &carry_out)
{
    dummy_cfixedpoint.resize(Sub_CtCt_FixedPoint(a.size(), carry_in, carry_out));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::Add_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b, const bool &carry_in, const bool &carry_out)
{
    dummy_cfixedpoint.resize(Add_CtPt_FixedPoint(b, carry_in, carry_out));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::Sub_PtCt_FixedPoint(const PFixedPoint &a, const CFixedPoint &b, const bool &carry_in, const bool &carry_out)
{
    dummy_cfixedpoint.resize(Sub_PtCt_FixedPoint(a, carry_in, carry_out));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::Neg_Ct_FixedPoint(const CFixedPoint &a)
{
    dummy_cfixedpoint.resize(Neg_Ct_FixedPoint(a.size()));
    return dummy_cfixedpoint;
}

LWECiphertext BaseAESimulator::CmpNotEq_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b)
{
    CmpNotEq_CtCt_FixedPoint(a.size());
    return dummy_ct;
}

LWECiphertext BaseAESimulator::CmpEq_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b)
{
    CmpEq_CtCt_FixedPoint(a.size());
    return dummy_ct;
}

LWECiphertext BaseAESimulator::CmpLTEq_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b)
{
    CmpLTEq_U_CtCt_FixedPoint(a.size());
    return dummy_ct;
}

LWECiphertext BaseAESimulator::CmpGT_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b)
{
    CmpGT_U_CtCt_FixedPoint(a.size());
    return dummy_ct;
}

LWECiphertext BaseAESimulator::CmpNotEq_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b)
{
    CmpNotEq_CtPt_FixedPoint(b);
    return dummy_ct;
}

LWECiphertext BaseAESimulator::CmpEq_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b)
{
    CmpEq_CtPt_FixedPoint(b);
    return dummy_ct;
}

LWECiphertext BaseAESimulator::CmpLTEq_U_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b)
{
    CmpLTEq_U_CtPt_FixedPoint(b);
    return dummy_ct;
}

LWECiphertext BaseAESimulator::CmpGT_U_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b)
{
    CmpGT_U_CtPt_FixedPoint(b);
    return dummy_ct;
}

CFixedPoint BaseAESimulator::FullMul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b)
{
    dummy_cfixedpoint.resize(FullMul_CtCt_FixedPoint(a.size()));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::FullMul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b)
{
    dummy_cfixedpoint.resize(FullMul_CtPt_FixedPoint(a.size(), b));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::FullMulFast_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b)
{
    dummy_cfixedpoint.resize(FullMulFast_CtPt_FixedPoint(a.size(), b));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::BoothsMul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b)
{
    dummy_cfixedpoint.resize(BoothsMul_CtPt_FixedPoint(a.size(), b));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::Mul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b)
{
    dummy_cfixedpoint.resize(Mul_CtCt_FixedPoint(a.size()));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::Mul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b)
{
    dummy_cfixedpoint.resize(Mul_CtPt_FixedPoint(b));
    return dummy_cfixedpoint;
}

CFixedPoint BaseAESimulator::MulFast_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b)
{
    dummy_cfixedpoint.resize(MulFast_CtPt_FixedPoint(b));
    return dummy_cfixedpoint;
}

LWECiphertext BaseAESimulator::Mux_CCC(LWECiphertext s, LWECiphertext a, LWECiphertext b)
{
    Mux_CCC();
    return dummy_ct;
}

LWECiphertext BaseAESimulator::Mux_CCP(LWECiphertext s, LWECiphertext a, LWEPlaintext b)
{
    Mux_CCP(b);
    return dummy_ct;
}

void BaseAESimulator::Mux_CPP(LWECiphertext s, LWEPlaintext a, LWEPlaintext b, LWECiphertext &out_ct, LWEPlaintext &out_pt, bool &is_out_ct)
{
    Mux_CPP(a, b, out_pt, is_out_ct);
}

void BaseAESimulator::ANDOR()
{
    num_andor++;
    num_bs++;
}

void BaseAESimulator::XORXNOR()
{
    num_xorxnor++;
    num_bs++;
}

void BaseAESimulator::MAJ()
{
    num_maj++;
    num_bs++;
}

size_t BaseAESimulator::SimAdd(const size_t n_bits)
{
    return Add_CtCt_FixedPoint(n_bits, false, true);
}

size_t BaseAESimulator::SimAddC(const size_t n_bits)
{
    return Add_CtCt_FixedPoint(n_bits, true, true);
}

size_t BaseAESimulator::SimAddNC(const size_t n_bits)
{
    return Add_CtCt_FixedPoint(n_bits, false, false);
}

size_t BaseAESimulator::SimAddCNC(const size_t n_bits)
{
    return Add_CtCt_FixedPoint(n_bits, true, false);
}

size_t BaseAESimulator::SimSub(const size_t n_bits)
{
    return Sub_CtCt_FixedPoint(n_bits, false, true);
}

size_t BaseAESimulator::SimSubC(const size_t n_bits)
{
    return Sub_CtCt_FixedPoint(n_bits, true, true);
}

size_t BaseAESimulator::SimSubNC(const size_t n_bits)
{
    return Sub_CtCt_FixedPoint(n_bits, false, false);
}

size_t BaseAESimulator::SimSubCNC(const size_t n_bits)
{
    return Sub_CtCt_FixedPoint(n_bits, true, false);
}

size_t BaseAESimulator::SimAdd(const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, false, true);
}

size_t BaseAESimulator::SimAddC(const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, true, true);
}

size_t BaseAESimulator::SimAddNC(const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, false, false);
}

size_t BaseAESimulator::SimAddCNC(const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, true, false);
}

size_t BaseAESimulator::SimSub(const int a, const PFixedPoint &b)
{
    return SimAdd(BaseArithmeticsEngine::Neg(b));
}

size_t BaseAESimulator::SimSub(const PFixedPoint &a)
{
    return Sub_PtCt_FixedPoint(a, false, true);
}

size_t BaseAESimulator::SimSubC(const int a, const PFixedPoint &b)
{
    return SimAddC(BaseArithmeticsEngine::Not(b));
}

size_t BaseAESimulator::SimSubC(const PFixedPoint &a)
{
    return Sub_PtCt_FixedPoint(a, true, true);
}

size_t BaseAESimulator::SimSubNC(const int a, const PFixedPoint &b)
{
    return SimAddNC(BaseArithmeticsEngine::Neg(b));
}

size_t BaseAESimulator::SimSubNC(const PFixedPoint &a)
{
    return Sub_PtCt_FixedPoint(a, false, false);
}

size_t BaseAESimulator::SimSubCNC(const int a, const PFixedPoint &b)
{
    return SimAddCNC(BaseArithmeticsEngine::Not(b));
}

size_t BaseAESimulator::SimSubCNC(const PFixedPoint &a)
{
    return Sub_PtCt_FixedPoint(a, true, false);
}

void BaseAESimulator::SimCmpNotEq(const size_t n_bits)
{
    return CmpNotEq_CtCt_FixedPoint(n_bits);
}

void BaseAESimulator::SimCmpNotEq(const PFixedPoint &b)
{
    return CmpNotEq_CtPt_FixedPoint(b);
}

void BaseAESimulator::SimCmpEq(const size_t n_bits)
{
    return CmpEq_CtCt_FixedPoint(n_bits);
}

void BaseAESimulator::SimCmpEq(const PFixedPoint &b)
{
    return CmpEq_CtPt_FixedPoint(b);
}

void BaseAESimulator::SimCmpLTEq_U(const size_t n_bits)
{
    return CmpLTEq_U_CtCt_FixedPoint(n_bits);
}

void BaseAESimulator::SimCmpLTEq_U(const int a, const PFixedPoint &b)
{
    return CmpLTEq_U_CtPt_FixedPoint(b);
}

void BaseAESimulator::SimCmpLTEq_U(const PFixedPoint &a)
{
    return SimCmpGTEq_U(0, a);
}

void BaseAESimulator::SimCmpGT_U(const size_t n_bits)
{
    return CmpGT_U_CtCt_FixedPoint(n_bits);
}

void BaseAESimulator::SimCmpGT_U(const int a, const PFixedPoint &b)
{
    return CmpGT_U_CtPt_FixedPoint(b);
}

void BaseAESimulator::SimCmpGT_U(const PFixedPoint &a)
{
    return SimCmpLT_U(0, a);
}

void BaseAESimulator::SimCmpGTEq_U(const size_t n_bits)
{
    return CmpLTEq_U_CtCt_FixedPoint(n_bits);
}

void BaseAESimulator::SimCmpGTEq_U(const int a, const PFixedPoint &b)
{
    SimNot(b.size());
    return CmpLTEq_U_CtPt_FixedPoint(BaseArithmeticsEngine::Not(b));
}

void BaseAESimulator::SimCmpGTEq_U(const PFixedPoint &a)
{
    return CmpLTEq_U_CtPt_FixedPoint(a);
}

void BaseAESimulator::SimCmpLT_U(const size_t n_bits)
{
    return CmpGT_U_CtCt_FixedPoint(n_bits);
}

void BaseAESimulator::SimCmpLT_U(const int a, const PFixedPoint &b)
{
    SimNot(b.size());
    return CmpGT_U_CtPt_FixedPoint(BaseArithmeticsEngine::Not(b));
}

void BaseAESimulator::SimCmpLT_U(const PFixedPoint &a)
{
    return CmpGT_U_CtPt_FixedPoint(a);
}

void BaseAESimulator::SimCmpLTEq(const size_t n_bits)
{
    SimToggleMSB(n_bits);
    SimToggleMSB(n_bits);
    return SimCmpLTEq_U(n_bits);
}

void BaseAESimulator::SimCmpLTEq(const int a, const PFixedPoint &b)
{
    SimToggleMSB(b.size());
    return SimCmpLTEq_U(a, BaseArithmeticsEngine::ToggleMSB(b));
}

void BaseAESimulator::SimCmpLTEq(const PFixedPoint &a)
{
    SimToggleMSB(a.size());
    return SimCmpLTEq_U(BaseArithmeticsEngine::ToggleMSB(a));
}

void BaseAESimulator::SimCmpGT(const size_t n_bits)
{
    SimToggleMSB(n_bits);
    SimToggleMSB(n_bits);
    return SimCmpGT_U(n_bits);
}

void BaseAESimulator::SimCmpGT(const int a, const PFixedPoint &b)
{
    SimToggleMSB(b.size());
    return SimCmpGT_U(a, BaseArithmeticsEngine::ToggleMSB(b));
}

void BaseAESimulator::SimCmpGT(const PFixedPoint &a)
{
    SimToggleMSB(a.size());
    return SimCmpGT_U(BaseArithmeticsEngine::ToggleMSB(a));
}

void BaseAESimulator::SimCmpGTEq(const size_t n_bits)
{
    SimToggleMSB(n_bits);
    SimToggleMSB(n_bits);
    return SimCmpGTEq_U(n_bits);
}

void BaseAESimulator::SimCmpGTEq(const int a, const PFixedPoint &b)
{
    SimToggleMSB(b.size());
    return SimCmpGTEq_U(a, BaseArithmeticsEngine::ToggleMSB(b));
}

void BaseAESimulator::SimCmpGTEq(const PFixedPoint &a)
{
    SimToggleMSB(a.size());
    return SimCmpGTEq_U(BaseArithmeticsEngine::ToggleMSB(a));
}

void BaseAESimulator::SimCmpLT(const size_t n_bits)
{
    SimToggleMSB(n_bits);
    SimToggleMSB(n_bits);
    return SimCmpLT_U(n_bits);
}

void BaseAESimulator::SimCmpLT(const int a, const PFixedPoint &b)
{
    SimToggleMSB(b.size());
    return SimCmpLT_U(a, BaseArithmeticsEngine::ToggleMSB(b));
}

void BaseAESimulator::SimCmpLT(const PFixedPoint &a)
{
    SimToggleMSB(a.size());
    return SimCmpLT_U(BaseArithmeticsEngine::ToggleMSB(a));
}

size_t BaseAESimulator::SimToggleMSB(const size_t n_bits)
{
    num_not++;
    return n_bits;
}

size_t BaseAESimulator::SimNeg(const size_t n_bits)
{
    return Neg_Ct_FixedPoint(n_bits);
}

size_t BaseAESimulator::SimNot(const size_t n_bits)
{
    num_not += n_bits;
    return n_bits;
}

size_t BaseAESimulator::SimFullMul(const size_t n_bits)
{
    return FullMul_CtCt_FixedPoint(n_bits);
}

size_t BaseAESimulator::SimFullMul(const size_t n_bits, const PFixedPoint &b)
{
    return FullMul_CtPt_FixedPoint(n_bits, b);
}

size_t BaseAESimulator::SimFullMulFast(const size_t n_bits, const PFixedPoint &b)
{
    return FullMulFast_CtPt_FixedPoint(n_bits, b);
}

size_t BaseAESimulator::SimBoothsMul(const size_t n_bits, const PFixedPoint &b)
{
    return BoothsMul_CtPt_FixedPoint(n_bits, b);
}

size_t BaseAESimulator::SimMul(const size_t n_bits)
{
    return Mul_CtCt_FixedPoint(n_bits);
}

size_t BaseAESimulator::SimMul(const PFixedPoint &b)
{
    return Mul_CtPt_FixedPoint(b);
}

size_t BaseAESimulator::SimMulFast(const PFixedPoint &b)
{
    return MulFast_CtPt_FixedPoint(b);
}

void BaseAESimulator::SimMux()
{
    Mux_CCC();
}

void BaseAESimulator::SimMux(LWEPlaintext b)
{
    Mux_CCP(b);
}

void BaseAESimulator::SimMux(int s, LWEPlaintext a)
{
    num_not++;
    Mux_CCP(a);
}

void BaseAESimulator::SimMux(LWEPlaintext a, LWEPlaintext b, LWEPlaintext &out_pt, bool &is_out_ct)
{
    Mux_CPP(a, b, out_pt, is_out_ct);
}

size_t BaseAESimulator::SimMux(const size_t n_bits)
{
    for (size_t i = 0; i < n_bits; i++)
    {
        SimMux();
    }
    return n_bits;
}

size_t BaseAESimulator::SimMux(const PFixedPoint b)
{
    for (size_t i = 0; i < b.size(); i++)
    {
        SimMux(b[i]);
    }
    return b.size();
}

size_t BaseAESimulator::SimMux(int s, const PFixedPoint a)
{
    for (size_t i = 0; i < a.size(); i++)
    {
        SimMux(s, a[i]);
    }
    return a.size();
}

CFixedPoint BaseAESimulator::ToggleMSB(const CFixedPoint &a)
{
    num_not++;
    return a;
}

LWECiphertext BaseAESimulator::PXOR(ConstLWECiphertext &a, const LWEPlaintext &b)
{
    if (b == 0)
    {
        return dummy_ct;
    }
    num_not++;
    return dummy_ct;
}

CFixedPoint BaseAESimulator::Not(const CFixedPoint &a)
{
    num_not += a.size();
    return a;
}

LWECiphertext BaseAESimulator::Mux(LWECiphertext s, LWEPlaintext a, LWECiphertext b)
{
    num_not++;
    return BaseArithmeticsEngine::Mux(s, b, a);
}

void BaseAESimulator::init_error()
{
    error_andor = get_error_andor();
    error_xorxnor = get_error_xorxnor();
    error_xor3 = get_error_xor3();
    error_maj = get_error_maj();
    error_ma = get_error_ma();
    error_mac = get_error_mac();
    error_ds = get_error_ds();
    error_mux = get_error_mux();
}

long double BaseAESimulator::get_error_andor()
{
    double s = bs_stdev[cfhe_base->GetCryptoContextParam()];
    return erfc((1. / 8.) / (2. * s));
}

long double BaseAESimulator::get_error_xorxnor()
{
    double s = bs_stdev[cfhe_base->GetCryptoContextParam()];
    return erfc((1. / 4.) / (4. * s));
}

long double BaseAESimulator::get_error_xor3()
{
    double s = bs_stdev[cfhe_base->GetCryptoContextParam()];
    return erfc((1. / 4.) / (2. * sqrtl(6.) * s));
}

long double BaseAESimulator::get_error_maj()
{
    double s = bs_stdev[cfhe_base->GetCryptoContextParam()];
    return erfc((1. / 8.) / (sqrtl(6.) * s));
}

long double BaseAESimulator::get_error_ma()
{
    double s = bs_stdev[cfhe_base->GetCryptoContextParam()];
    return erfc((1. / 8.) / (2. * sqrtl(3.) * s));
}

long double BaseAESimulator::get_error_mac()
{
    long double e1 = get_error_ma();
    long double e2 = get_error_andor();
    return e1 + e2 - e1 * e2;
}

long double BaseAESimulator::get_error_ds()
{
    double s = bs_stdev[cfhe_base->GetCryptoContextParam()];
    return erfc((1. / 8.) / (2. * sqrtl(3.) * s));
}

long double BaseAESimulator::get_error_mux()
{
    double s = bs_stdev[cfhe_base->GetCryptoContextParam()];
    long double e1 = erfc((1. / 8.) / (2. * sqrtl(3.) * s));
    long double e2 = get_error_andor();
    return e1 + e2 - e1 * e2;
}
