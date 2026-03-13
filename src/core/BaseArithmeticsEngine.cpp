#include <computefhe/BaseArithmeticsEngine.h>
#include <cassert>
using namespace computefhe;

BaseArithmeticsEngine::BaseArithmeticsEngine(ComputeFHE *cfhe) : cfhe_base(cfhe)
{
    ResetCarry();
}

BaseArithmeticsEngine::~BaseArithmeticsEngine()
{
}

ComputeFHE *BaseArithmeticsEngine::GetBase()
{
    return cfhe_base;
}

LWECiphertext BaseArithmeticsEngine::GetCarry()
{
    return carry;
}

LWEPlaintext BaseArithmeticsEngine::GetCarryPT()
{
    return carry_pt;
}

void BaseArithmeticsEngine::SetCarry(LWEPlaintext value)
{
    carry_pt = value;
    is_lastcarry_ct = false;
}

void BaseArithmeticsEngine::SetCarry(LWECiphertext value)
{
    carry = COPY_CT(value);
    is_lastcarry_ct = true;
}

void BaseArithmeticsEngine::SetCarry()
{
    carry = GetConstantTrue();
    carry_pt = 1;
    is_lastcarry_ct = false;
}

void BaseArithmeticsEngine::ResetCarry()
{
    carry = GetConstantFalse();
    carry_pt = 0;
    is_lastcarry_ct = false;
}

bool BaseArithmeticsEngine::isLastCarryCT()
{
    return is_lastcarry_ct;
}

void BaseArithmeticsEngine::SetIsLastCarryCT(bool val)
{
    is_lastcarry_ct = val;
}

LWECiphertext BaseArithmeticsEngine::GetConstantFalse()
{
    LWECiphertext constant_false = cfhe_base->GetBinFHEContext().EvalConstant(false);
    return COPY_CT(constant_false);
}

LWECiphertext BaseArithmeticsEngine::GetConstantTrue()
{
    LWECiphertext constant_true = cfhe_base->GetBinFHEContext().EvalConstant(true);
    return COPY_CT(constant_true);
}

CFixedPoint BaseArithmeticsEngine::Add(const CFixedPoint &a, const CFixedPoint &b)
{
    return Add_CtCt_FixedPoint(a, b, false, true);
}

CFixedPoint BaseArithmeticsEngine::AddC(const CFixedPoint &a, const CFixedPoint &b)
{
    return Add_CtCt_FixedPoint(a, b, true, true);
}

CFixedPoint BaseArithmeticsEngine::AddNC(const CFixedPoint &a, const CFixedPoint &b)
{
    return Add_CtCt_FixedPoint(a, b, false, false);
}

CFixedPoint BaseArithmeticsEngine::AddCNC(const CFixedPoint &a, const CFixedPoint &b)
{
    return Add_CtCt_FixedPoint(a, b, true, false);
}

CFixedPoint BaseArithmeticsEngine::Sub(const CFixedPoint &a, const CFixedPoint &b)
{
    return Sub_CtCt_FixedPoint(a, b, false, true);
}

CFixedPoint BaseArithmeticsEngine::SubC(const CFixedPoint &a, const CFixedPoint &b)
{
    return Sub_CtCt_FixedPoint(a, b, true, true);
}

CFixedPoint BaseArithmeticsEngine::SubNC(const CFixedPoint &a, const CFixedPoint &b)
{
    return Sub_CtCt_FixedPoint(a, b, false, false);
}

CFixedPoint BaseArithmeticsEngine::SubCNC(const CFixedPoint &a, const CFixedPoint &b)
{
    return Sub_CtCt_FixedPoint(a, b, true, false);
}

CFixedPoint BaseArithmeticsEngine::Add(const CFixedPoint &a, const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(a, b, false, true);
}

CFixedPoint BaseArithmeticsEngine::Add(const PFixedPoint &a, const CFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, a, false, true);
}

CFixedPoint BaseArithmeticsEngine::AddC(const CFixedPoint &a, const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(a, b, true, true);
}

CFixedPoint BaseArithmeticsEngine::AddC(const PFixedPoint &a, const CFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, a, true, true);
}

CFixedPoint BaseArithmeticsEngine::AddNC(const CFixedPoint &a, const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(a, b, false, false);
}

CFixedPoint BaseArithmeticsEngine::AddNC(const PFixedPoint &a, const CFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, a, false, false);
}

CFixedPoint BaseArithmeticsEngine::AddCNC(const CFixedPoint &a, const PFixedPoint &b)
{
    return Add_CtPt_FixedPoint(a, b, true, false);
}

CFixedPoint BaseArithmeticsEngine::AddCNC(const PFixedPoint &a, const CFixedPoint &b)
{
    return Add_CtPt_FixedPoint(b, a, true, false);
}

CFixedPoint BaseArithmeticsEngine::Sub(const CFixedPoint &a, const PFixedPoint &b)
{
    return Add(a, Neg(b));
}

CFixedPoint BaseArithmeticsEngine::Sub(const PFixedPoint &a, const CFixedPoint &b)
{
    return Sub_PtCt_FixedPoint(a, b, false, true);
}

CFixedPoint BaseArithmeticsEngine::SubC(const CFixedPoint &a, const PFixedPoint &b)
{
    return AddC(a, Not(b));
}

CFixedPoint BaseArithmeticsEngine::SubC(const PFixedPoint &a, const CFixedPoint &b)
{
    return Sub_PtCt_FixedPoint(a, b, true, true);
}

CFixedPoint BaseArithmeticsEngine::SubNC(const CFixedPoint &a, const PFixedPoint &b)
{
    return AddNC(a, Neg(b));
}

CFixedPoint BaseArithmeticsEngine::SubNC(const PFixedPoint &a, const CFixedPoint &b)
{
    return Sub_PtCt_FixedPoint(a, b, false, false);
}

CFixedPoint BaseArithmeticsEngine::SubCNC(const CFixedPoint &a, const PFixedPoint &b)
{
    return AddCNC(a, Not(b));
}

CFixedPoint BaseArithmeticsEngine::SubCNC(const PFixedPoint &a, const CFixedPoint &b)
{
    return Sub_PtCt_FixedPoint(a, b, true, false);
}

LWECiphertext BaseArithmeticsEngine::CmpNotEq(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpNotEq_CtCt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpNotEq(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpNotEq_CtPt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpNotEq(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpNotEq_CtPt_FixedPoint(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpEq(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpEq_CtCt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpEq(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpEq_CtPt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpEq(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpEq_CtPt_FixedPoint(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U_CtCt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpLTEq_U(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpLTEq_U_CtPt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpLTEq_U(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpGTEq_U(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpGT_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U_CtCt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpGT_U(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpGT_U_CtPt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpGT_U(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpLT_U(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpGTEq_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U_CtCt_FixedPoint(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpGTEq_U(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpLTEq_U_CtPt_FixedPoint(Not(a), Not(b));
}

LWECiphertext BaseArithmeticsEngine::CmpGTEq_U(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U_CtPt_FixedPoint(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpLT_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U_CtCt_FixedPoint(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpLT_U(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpGT_U_CtPt_FixedPoint(Not(a), Not(b));
}

LWECiphertext BaseArithmeticsEngine::CmpLT_U(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U_CtPt_FixedPoint(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpLTEq(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpLTEq(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpLTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpLTEq(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpGT(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpGT(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpGT_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpGT(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpGTEq(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpGTEq(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpGTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpGTEq(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpGTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpLT(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLT_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpLT(const CFixedPoint &a, const PFixedPoint &b)
{
    return CmpLT_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpLT(const PFixedPoint &a, const CFixedPoint &b)
{
    return CmpLT_U(ToggleMSB(a), ToggleMSB(b));
}

CFixedPoint BaseArithmeticsEngine::ToggleMSB(const CFixedPoint &a)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    CFixedPoint t = CFixedPoint(a);
    t.back() = cc.EvalNOT(t.back());
    return t;
}

PFixedPoint BaseArithmeticsEngine::ToggleMSB(const PFixedPoint &a)
{
    PFixedPoint t = a;
    t.back() = 1U - t.back();
    return t;
}

LWECiphertext BaseArithmeticsEngine::PXOR(ConstLWECiphertext &a, const LWEPlaintext &b)
{
    return (b == 0) ? COPY_CT(a) : cfhe_base->GetBinFHEContext().EvalNOT(a);
}

LWECiphertext BaseArithmeticsEngine::PXOR(const LWEPlaintext &a, ConstLWECiphertext &b)
{
    return PXOR(b, a);
}

LWEPlaintext BaseArithmeticsEngine::PXOR(const LWEPlaintext &a, LWEPlaintext &b)
{
    return (a == b) ? 0 : 1;
}

LWECiphertext BaseArithmeticsEngine::PXNOR(ConstLWECiphertext &a, const LWEPlaintext &b)
{
    return PXOR(a, 1 - b);
}

LWECiphertext BaseArithmeticsEngine::PXNOR(const LWEPlaintext &a, ConstLWECiphertext &b)
{
    return PXNOR(b, a);
}

LWEPlaintext BaseArithmeticsEngine::PXNOR(const LWEPlaintext &a, LWEPlaintext &b)
{
    return (a == b) ? 1 : 0;
}

CFixedPoint BaseArithmeticsEngine::Neg(const CFixedPoint &a)
{
    return Neg_Ct_FixedPoint(a);
}

PFixedPoint BaseArithmeticsEngine::Neg(const PFixedPoint &a)
{
    return PFixedPoint(cfhe_base->uint2PFixedPoint(UINT32_MAX - cfhe_base->PFixedPoint2uint(a) + 1U, a.size()));
}

CFixedPoint BaseArithmeticsEngine::Not(const CFixedPoint &a)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    CFixedPoint out(a.size());
    for (size_t i = 0; i < a.size(); i++)
    {
        out[i] = cc.EvalNOT(a[i]);
    }
    return out;
}

PFixedPoint BaseArithmeticsEngine::Not(const PFixedPoint &a)
{
    return PFixedPoint(cfhe_base->uint2PFixedPoint(UINT32_MAX - cfhe_base->PFixedPoint2uint(a), a.size()));
}

CFixedPoint BaseArithmeticsEngine::FullMul(const CFixedPoint &a, const CFixedPoint &b)
{
    return FullMul_CtCt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::FullMul(const CFixedPoint &a, const PFixedPoint &b)
{
    return FullMul_CtPt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::FullMul(const PFixedPoint &a, const CFixedPoint &b)
{
    return FullMul_CtPt_FixedPoint(b, a);
}

CFixedPoint BaseArithmeticsEngine::FullMulFast(const CFixedPoint &a, const PFixedPoint &b)
{
    return FullMulFast_CtPt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::FullMulFast(const PFixedPoint &a, const CFixedPoint &b)
{
    return FullMul_CtPt_FixedPoint(b, a);
}

CFixedPoint BaseArithmeticsEngine::BoothsMul(const CFixedPoint &a, const PFixedPoint &b)
{
    return BoothsMul_CtPt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::BoothsMul(const PFixedPoint &a, const CFixedPoint &b)
{
    return BoothsMul_CtPt_FixedPoint(b, a);
}

CFixedPoint BaseArithmeticsEngine::Mul(const CFixedPoint &a, const CFixedPoint &b)
{
    return Mul_CtCt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::Mul(const CFixedPoint &a, const PFixedPoint &b)
{
    return Mul_CtPt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::Mul(const PFixedPoint &a, const CFixedPoint &b)
{
    return Mul_CtPt_FixedPoint(b, a);
}

CFixedPoint BaseArithmeticsEngine::MulFast(const CFixedPoint &a, const PFixedPoint &b)
{
    return MulFast_CtPt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::MulFast(const PFixedPoint &a, const CFixedPoint &b)
{
    return MulFast_CtPt_FixedPoint(b, a);
}

LWECiphertext BaseArithmeticsEngine::Mux(LWECiphertext s, LWECiphertext a, LWECiphertext b)
{
    return Mux_CCC(s, a, b);
}

LWECiphertext BaseArithmeticsEngine::Mux(LWECiphertext s, LWECiphertext a, LWEPlaintext b)
{
    return Mux_CCP(s, a, b);
}

LWECiphertext BaseArithmeticsEngine::Mux(LWECiphertext s, LWEPlaintext a, LWECiphertext b)
{
    return Mux_CCP(cfhe_base->GetBinFHEContext().EvalNOT(s), b, a);
}

void BaseArithmeticsEngine::Mux(LWECiphertext s, LWEPlaintext a, LWEPlaintext b,
                                LWECiphertext &out_ct, LWEPlaintext &out_pt, bool &is_out_ct)
{
    return Mux_CPP(s, a, b, out_ct, out_pt, is_out_ct);
}

CFixedPoint BaseArithmeticsEngine::Mux(LWECiphertext s, const CFixedPoint a, const CFixedPoint b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (size_t i = 0; i < n_digit; i++)
    {
        out[i] = Mux(s, a[i], b[i]);
    }
    return out;
}

CFixedPoint BaseArithmeticsEngine::Mux(LWECiphertext s, const CFixedPoint a, const PFixedPoint b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (size_t i = 0; i < n_digit; i++)
    {
        out[i] = Mux(s, a[i], b[i]);
    }
    return out;
}

CFixedPoint BaseArithmeticsEngine::Mux(LWECiphertext s, const PFixedPoint a, const CFixedPoint b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (size_t i = 0; i < n_digit; i++)
    {
        out[i] = Mux(s, a[i], b[i]);
    }
    return out;
}
