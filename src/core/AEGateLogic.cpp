#include <computefhe/AEGateLogic.h>
#include <cassert>
using namespace computefhe;

AEGateLogic::AEGateLogic(ComputeFHE *cfhe) : BaseArithmeticsEngine(cfhe)
{
}

void AEGateLogic::HalfAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                            LWECiphertext &sum, LWECiphertext &carry_out)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    sum = cc.EvalBinGate(XOR, a, b);
    carry_out = cc.EvalBinGate(AND, a, b);
}

void AEGateLogic::HalfSubtractor(ConstLWECiphertext &a, ConstLWECiphertext &b,
                                 LWECiphertext &sum, LWECiphertext &carry_out)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    sum = cc.EvalBinGate(XOR, a, b);
    carry_out = cc.EvalBinGate(OR, a, cc.EvalNOT(b));
}

void AEGateLogic::FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c,
                            LWECiphertext &sum, LWECiphertext &carry_out)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    sum = cc.EvalBinGate(XOR, a, b);
    LWECiphertext carry1 = cc.EvalBinGate(AND, a, b);
    LWECiphertext carry2 = cc.EvalBinGate(AND, sum, c);
    sum = cc.EvalBinGate(XOR, sum, c);
    carry_out = cc.EvalBinGate(OR, carry1, carry2);
}

LWECiphertext AEGateLogic::XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    LWECiphertext sum = cc.EvalBinGate(XOR, a, b);
    sum = cc.EvalBinGate(XOR, sum, c);
    return sum;
}

LWECiphertext AEGateLogic::MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                                  LWECiphertext *carry_out)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    LWECiphertext ma = cc.EvalBinGate(AND, m, a);
    LWECiphertext sum = cc.EvalBinGate(XOR, ma, b);
    if (carry_out)
    {
        *carry_out = cc.EvalBinGate(AND, ma, b);
    }
    return sum;
}

FixedPoint AEGateLogic::Add(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfAdder(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        FullAdder(a[i], b[i], carry, out[i], carry);
    }
    return out;
}

FixedPoint AEGateLogic::AddC(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        FullAdder(a[i], b[i], carry, out[i], carry);
    }
    return out;
}

FixedPoint AEGateLogic::AddNC(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfAdder(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        if (i < n_digit - 1)
        {
            FullAdder(a[i], b[i], carry, out[i], carry);
        }
        else
        {
            out[i] = XOR3(a[i], b[i], carry);
        }
    }
    return out;
}

FixedPoint AEGateLogic::Sub(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfSubtractor(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        LWECiphertext inv_b = cc.EvalNOT(b[i]);
        FullAdder(a[i], inv_b, carry, out[i], carry);
    }
    return out;
}

FixedPoint AEGateLogic::SubC(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        LWECiphertext inv = cc.EvalNOT(b[i]);
        FullAdder(a[i], inv, carry, out[i], carry);
    }
    return out;
}

FixedPoint AEGateLogic::SubNC(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfSubtractor(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        LWECiphertext inv_b = cc.EvalNOT(b[i]);
        if (i < n_digit - 1)
        {
            FullAdder(a[i], inv_b, carry, out[i], carry);
        }
        else
        {
            out[i] = XOR3(a[i], inv_b, carry);
        }
    }
    return out;
}

FixedPoint AEGateLogic::Neg(const FixedPoint &a)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    out[0] = COPY_CT(a[0]);
    LWECiphertext c = cc.EvalNOT(a[0]);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        LWECiphertext inv = cc.EvalNOT(a[i]);
        if (i < n_digit - 1)
        {
            HalfAdder(inv, c, out[i], c);
        }
        else
        {
            out[i] = cc.EvalBinGate(XOR, inv, c);
        }
    }
    return out;
}

LWECiphertext AEGateLogic::CmpNotEq(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    LWECiphertext out = cc.EvalBinGate(XOR, a[0], b[0]);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        LWECiphertext eq = cc.EvalBinGate(XOR, a[i], b[i]);
        out = cc.EvalBinGate(OR, out, eq);
    }
    return out;
}

LWECiphertext AEGateLogic::CmpEq(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    LWECiphertext out = cc.EvalBinGate(XNOR, a[0], b[0]);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        LWECiphertext eq = cc.EvalBinGate(XNOR, a[i], b[i]);
        out = cc.EvalBinGate(AND, out, eq);
    }
    return out;
}

LWECiphertext AEGateLogic::CmpLTEq_U(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    LWECiphertext inv_a = cc.EvalNOT(a[0]);
    LWECiphertext out = cc.EvalBinGate(OR, inv_a, b[0]);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        inv_a = cc.EvalNOT(a[i]);
        LWECiphertext t1 = cc.EvalBinGate(AND, inv_a, b[i]);
        LWECiphertext t2 = cc.EvalBinGate(OR, inv_a, b[i]);
        out = cc.EvalBinGate(AND, t2, out);
        out = cc.EvalBinGate(OR, t1, out);
    }
    return out;
}

LWECiphertext AEGateLogic::CmpGT_U(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    LWECiphertext inv_b = cc.EvalNOT(b[0]);
    LWECiphertext out = cc.EvalBinGate(AND, a[0], inv_b);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        inv_b = cc.EvalNOT(b[i]);
        LWECiphertext t1 = cc.EvalBinGate(AND, a[i], inv_b);
        LWECiphertext t2 = cc.EvalBinGate(OR, a[i], inv_b);
        out = cc.EvalBinGate(AND, t2, out);
        out = cc.EvalBinGate(OR, t1, out);
    }
    return out;
}

LWECiphertext AEGateLogic::CmpGTEq_U(const FixedPoint &a, const FixedPoint &b)
{
    return CmpLTEq_U(b, a);
}

LWECiphertext AEGateLogic::CmpLT_U(const FixedPoint &a, const FixedPoint &b)
{
    return CmpGT_U(b, a);
}

LWECiphertext AEGateLogic::CmpLTEq(const FixedPoint &a, const FixedPoint &b)
{
    return CmpLTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext AEGateLogic::CmpGT(const FixedPoint &a, const FixedPoint &b)
{
    return CmpGT_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext AEGateLogic::CmpGTEq(const FixedPoint &a, const FixedPoint &b)
{
    return CmpGTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext AEGateLogic::CmpLT(const FixedPoint &a, const FixedPoint &b)
{
    return CmpLT_U(ToggleMSB(a), ToggleMSB(b));
}

FixedPoint AEGateLogic::FullMul(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    // int bs = 0;

    FixedPoint out((n_digit == 1) ? 1 : (n_digit << 1));
    for (uint8_t i = 0; i < n_digit; i++)
    {
        out[i] = cc.EvalBinGate(AND, a[i], b[0]);
        // bs++;
    }
    for (uint8_t j = 1; j < n_digit; j++)
    {
        for (uint8_t i = 0; i < n_digit; i++)
        {
            LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
            // bs++;
            if (i == 0)
            {
                HalfAdder(out[i + j], p, out[i + j], carry);
                // bs += 2;
            }
            else if (i < n_digit - 1)
            {
                FullAdder(out[i + j], p, carry, out[i + j], carry);
                // bs += 5;
            }
            else if (j == 1)
            {
                HalfAdder(p, carry, out[i + j], out[i + j + 1]);
                // bs += 2;
            }
            else
            {
                FullAdder(out[i + j], p, carry, out[i + j], out[i + j + 1]);
                // bs += 5;
            }
        }
    }
    // cout << "BS = " << bs << endl;
    return out;
}

FixedPoint AEGateLogic::Mul(const FixedPoint &a, const FixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    // int bs = 0;

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        out[i] = cc.EvalBinGate(AND, a[i], b[0]);
        // bs++;
    }
    for (uint8_t j = 1; j < n_digit; j++)
    {
        for (uint8_t i = 0; i < n_digit - j; i++)
        {
            LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
            // bs++;
            if (i == 0 && j < n_digit - 1)
            {
                HalfAdder(out[i + j], p, out[i + j], carry);
                // bs += 2;
            }
            else if (i < n_digit - j - 1)
            {
                FullAdder(out[i + j], p, carry, out[i + j], carry);
                // bs += 5;
            }
            else if (j < n_digit - 1)
            {
                out[i + j] = cc.EvalBinGate(XOR, out[i + j], carry);
                out[i + j] = cc.EvalBinGate(XOR, out[i + j], p);
                // bs += 2;
            }
            else
            {
                out[i + j] = cc.EvalBinGate(XOR, out[i + j], p);
                // bs++;
            }
        }
    }
    // cout << "BS = " << bs << endl;
    return out;
}
