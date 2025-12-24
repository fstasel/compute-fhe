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

CFixedPoint BaseArithmeticsEngine::ToggleMSB(const CFixedPoint &a)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    CFixedPoint t = CFixedPoint(a);
    t.back() = cc.EvalNOT(t.back());
    return t;
}
