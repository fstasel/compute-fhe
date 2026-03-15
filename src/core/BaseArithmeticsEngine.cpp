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

LWECiphertext BaseArithmeticsEngine::GetCarry()
{
    return carry;
}

void BaseArithmeticsEngine::SetCarry(LWECiphertext value)
{
    carry = COPY_CT(value);
}

void BaseArithmeticsEngine::SetCarry()
{
    carry = GetConstantTrue();
}

void BaseArithmeticsEngine::ResetCarry()
{
    carry = GetConstantFalse();
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

FixedPoint BaseArithmeticsEngine::ToggleMSB(const FixedPoint &a)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    FixedPoint t = FixedPoint(a);
    t.back() = cc.EvalNOT(t.back());
    return t;
}
