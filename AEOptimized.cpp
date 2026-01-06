#include "AEOptimized.h"
#include <cassert>

AEOptimized::AEOptimized(ComputeFHE *cfhe) : AEGateLogic(cfhe)
{
}

void AEOptimized::FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c, LWECiphertext &sum, LWECiphertext &carry_out)
{
    LWECiphertext _a = COPY_CT(a);
    LWECiphertext _b = COPY_CT(b);
    LWECiphertext _c = COPY_CT(c);
    auto &cc = cfhe_base->GetBinFHEContext();
    sum = XOR3(_a, _b, _c);
    carry_out = cc.EvalBinGate(MAJORITY, {_a, _b, _c});
}

LWECiphertext AEOptimized::XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    LWECiphertext sum = COPY_CT(a);
    lwe->EvalAddEq(sum, b);
    sum = cc.EvalBinGate(XOR, sum, c);
    return sum;
}

LWECiphertext AEOptimized::MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                                  LWECiphertext *carry_out)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    LWECiphertext a_2b = COPY_CT(b);
    lwe->EvalAddEq(a_2b, a_2b);
    lwe->EvalAddEq(a_2b, a);
    LWECiphertext ma_2b = cc.EvalBinGate(AND, m, a_2b);
    if (carry_out)
    {
        LWECiphertext neg_b = COPY_CT(b);
        lwe->EvalMultConstEq(neg_b, -1);
        *carry_out = cc.EvalBinGate(AND, ma_2b, neg_b);
    }
    return ma_2b;
}

LWECiphertext AEOptimized::DigitSum(ConstLWECiphertext &e1, ConstLWECiphertext &e0, ConstLWECiphertext &s0)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    LWECiphertext s0_2e1_e0 = COPY_CT(e1);
    lwe->EvalAddEq(s0_2e1_e0, s0_2e1_e0);
    lwe->EvalSubEq(s0_2e1_e0, e0);
    s0_2e1_e0 = cc.EvalBinGate(AND, s0_2e1_e0, s0);
    return s0_2e1_e0;
}

LWECiphertext AEOptimized::CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    LWECiphertext inv_a = cc.EvalNOT(a[0]);
    LWECiphertext c = cc.EvalBinGate(OR, inv_a, b[0]);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        inv_a = cc.EvalNOT(a[i]);
        c = cc.EvalBinGate(MAJORITY, {inv_a, b[i], c});
    }
    return c;
}

LWECiphertext AEOptimized::CmpGT_U(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    LWECiphertext inv_b = cc.EvalNOT(b[0]);
    LWECiphertext c = cc.EvalBinGate(AND, a[0], inv_b);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        inv_b = cc.EvalNOT(b[i]);
        c = cc.EvalBinGate(MAJORITY, {a[i], inv_b, c});
    }
    return c;
}

CFixedPoint AEOptimized::FullMul(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out((n_digit == 1) ? 1 : (n_digit << 1));
    for (uint8_t i = 0; i < n_digit; i++)
    {
        out[i] = cc.EvalBinGate(AND, a[i], b[0]);
    }
    for (uint8_t j = 1; j < n_digit; j++)
    {
        for (uint8_t i = 0; i < n_digit; i++)
        {
            if (i == 0)
            {
                out[i + j] = MulAdd(a[i], b[j], out[i + j], &carry);
            }
            else if (i < n_digit - 1)
            {
                LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            }
            else if (j == 1)
            {
                out[i + j] = MulAdd(a[i], b[j], carry, &out[i + j + 1]);
            }
            else
            {
                LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], out[i + j + 1]);
            }
        }
    }
    return out;
}

CFixedPoint AEOptimized::Mul(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        out[i] = cc.EvalBinGate(AND, a[i], b[0]);
    }
    for (uint8_t j = 1; j < n_digit; j++)
    {
        for (uint8_t i = 0; i < n_digit - j; i++)
        {
            if (i == 0 && j < n_digit - 1)
            {
                out[i + j] = MulAdd(a[i], b[j], out[i + j], &carry);
            }
            else if (i < n_digit - j - 1)
            {
                LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            }
            else if (j < n_digit - 1)
            {
                LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
                out[i + j] = XOR3(out[i + j], carry, p);
            }
            else
            {
                out[i + j] = MulAdd(a[i], b[j], out[i + j]);
            }
        }
    }
    return out;
}

CFixedPoint AEOptimized::Add_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b,
                                             const bool &carry_in, const bool &carry_out)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        if (n_digit == 1 && !carry_in && !carry_out)
        {
            out[0] = PXOR(a[0], b[0]);
        }
        else if (n_digit == 1 && carry_in && !carry_out)
        {
            if (is_lastcarry_ct)
            {
                out[0] = PXOR(cc.EvalBinGate(XOR, a[0], carry), b[0]);
            }
            else
            {
                out[0] = PXOR(PXOR(a[0], b[0]), carry_pt);
            }
        }
        else if (i == 0 && !carry_in)
        {
            HalfAdder(a[0], b[0], out[0], carry, carry_pt, is_lastcarry_ct);
        }
        else if (i == n_digit - 1 && !carry_out)
        {
            if (is_lastcarry_ct)
            {
                out[i] = PXOR(DigitSum(PXOR(a[i], b[i - 1]), PXOR(a[i - 1], b[i - 1]), PXOR(out[i - 1], b[i - 1])), b[i]);
            }
            else if (b[i] == carry_pt)
            {
                out[i] = COPY_CT(a[i]);
            }
            else
            {
                out[i] = cc.EvalNOT(a[i]);
            }
        }
        else if (i == 0)
        {
            if (is_lastcarry_ct)
            {
                AEGateLogic::FullAdder(a[0], carry, b[0], out[0], carry);
            }
            else
            {
                AEGateLogic::FullAdder(a[0], b[0], carry_pt, out[0], carry, carry_pt, is_lastcarry_ct);
            }
        }
        else if (is_lastcarry_ct)
        {
            out[i] = PXOR(DigitSum(PXOR(a[i], b[i - 1]), PXOR(a[i - 1], b[i - 1]), PXOR(out[i - 1], b[i - 1])), b[i]);
            if (i == n_digit - 1)
            {
                carry = cc.EvalBinGate((b[i] == 0) ? AND : OR, a[i], cc.EvalNOT(out[i]));
            }
        }
        else
        {
            AEGateLogic::FullAdder(a[i], b[i], carry_pt, out[i], carry, carry_pt, is_lastcarry_ct);
        }
    }
    return out;
}

CFixedPoint AEOptimized::Sub_PtCt_FixedPoint(const PFixedPoint &a, const CFixedPoint &b, const bool &carry_in, const bool &carry_out)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        if (n_digit == 1 && !carry_in && !carry_out)
        {
            out[0] = PXOR(b[0], a[0]);
        }
        else if (n_digit == 1 && carry_in && !carry_out)
        {
            if (is_lastcarry_ct)
            {
                out[0] = PXOR(cc.EvalBinGate(XNOR, b[0], carry), a[0]);
            }
            else
            {
                out[0] = PXOR(PXNOR(b[0], a[0]), carry_pt);
            }
        }
        else if (i == 0 && !carry_in)
        {
            HalfSubtractor(a[0], b[0], out[0], carry, carry_pt, is_lastcarry_ct);
        }
        else if (i == n_digit - 1 && !carry_out)
        {
            if (is_lastcarry_ct)
            {
                out[i] = PXOR(DigitSum(PXNOR(b[i], a[i - 1]), PXNOR(b[i - 1], a[i - 1]), PXOR(out[i - 1], a[i - 1])), a[i]);
            }
            else if (a[i] != carry_pt)
            {
                out[i] = COPY_CT(b[i]);
            }
            else
            {
                out[i] = cc.EvalNOT(b[i]);
            }
        }
        else if (i == 0)
        {
            if (is_lastcarry_ct)
            {
                AEGateLogic::FullAdder(cc.EvalNOT(b[0]), carry, a[0], out[0], carry);
            }
            else
            {
                AEGateLogic::FullAdder(cc.EvalNOT(b[0]), a[0], carry_pt, out[0], carry, carry_pt, is_lastcarry_ct);
            }
        }
        else if (is_lastcarry_ct)
        {
            out[i] = PXOR(DigitSum(PXNOR(b[i], a[i - 1]), PXNOR(b[i - 1], a[i - 1]), PXOR(out[i - 1], a[i - 1])), a[i]);
            if (i == n_digit - 1)
            {
                carry = cc.EvalBinGate((a[i] == 0) ? NOR : NAND, b[i], out[i]);
            }
        }
        else
        {
            AEGateLogic::FullAdder(cc.EvalNOT(b[i]), a[i], carry_pt, out[i], carry, carry_pt, is_lastcarry_ct);
        }
    }
    return out;
}

CFixedPoint AEOptimized::Neg(const CFixedPoint &a)
{
    return SubNC(PFixedPoint(a.size(), 0), a);
}

uint AEOptimized::Get_CtCtAdd_Cost(size_t n_bits)
{
    return (n_bits > 0) ? 2 * n_bits : 0;
}

uint AEOptimized::Get_CtCtSubC_Cost(size_t n_bits)
{
    return (n_bits > 0) ? 2 * n_bits : 0;
}

uint AEOptimized::Get_CtPtAddC_Cost(size_t n_bits)
{
    return (n_bits > 0) ? n_bits + 2 : 0;
}

uint AEOptimized::Get_PtCtSub_Cost(size_t n_bits)
{
    return (n_bits > 0) ? n_bits + 1 : 0;
}

uint AEOptimized::Get_CtPtSubCNC_Cost(size_t n_bits)
{
    return (n_bits > 0) ? n_bits + 1 : 0;
}