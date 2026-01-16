#include "BaseArithmeticsEngine.h"

BaseArithmeticsEngine::BaseArithmeticsEngine(ComputeFHE *cfhe) : cfhe_base(cfhe)
{
    ResetCarry();
}

BaseArithmeticsEngine::~BaseArithmeticsEngine()
{
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

LWECiphertext BaseArithmeticsEngine::CmpEq(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpEq_CtCt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U_CtCt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpGT_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U_CtCt_FixedPoint(a, b);
}

LWECiphertext BaseArithmeticsEngine::CmpGTEq_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpLT_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U(b, a);
}

LWECiphertext BaseArithmeticsEngine::CmpLTEq(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpGT(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpGTEq(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext BaseArithmeticsEngine::CmpLT(const CFixedPoint &a, const CFixedPoint &b)
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

LWECiphertext BaseArithmeticsEngine::PXOR(ConstLWECiphertext &a, const LWEPlaintext &b)
{
    return (b == 0) ? COPY_CT(a) : cfhe_base->GetBinFHEContext().EvalNOT(a);
}

LWECiphertext BaseArithmeticsEngine::PXNOR(ConstLWECiphertext &a, const LWEPlaintext &b)
{
    return PXOR(a, 1 - b);
}

CFixedPoint BaseArithmeticsEngine::Neg(const CFixedPoint &a)
{
    return Neg_Ct_FixedPoint(a);
}

PFixedPoint BaseArithmeticsEngine::Neg(const PFixedPoint &a)
{
    return PFixedPoint(cfhe_base->uint2PFixedPoint(UINT32_MAX - cfhe_base->PFixedPoint2uint(a) + 1U, a.size()));
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

CFixedPoint BaseArithmeticsEngine::FullMulFast(const CFixedPoint &a, const PFixedPoint &b)
{
    return FullMulFast_CtPt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::BoothsMul(const CFixedPoint &a, const PFixedPoint &b)
{
    return BoothsMul_CtPt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::Mul(const CFixedPoint &a, const CFixedPoint &b)
{
    return Mul_CtCt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::Mul(const CFixedPoint &a, const PFixedPoint &b)
{
    return Mul_CtPt_FixedPoint(a, b);
}

CFixedPoint BaseArithmeticsEngine::MulFast(const CFixedPoint &a, const PFixedPoint &b)
{
    return MulFast_CtPt_FixedPoint(a, b);
}
