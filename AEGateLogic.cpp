#include "AEGateLogic.h"
#include <cassert>

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

void AEGateLogic::HalfAdder(ConstLWECiphertext &a, const LWEPlaintext &b,
                            LWECiphertext &sum, LWECiphertext &carry_out_ct,
                            LWEPlaintext &carry_out_pt, bool &is_carry_ct)
{
    if (b == 0)
    {
        sum = COPY_CT(a);
        carry_out_pt = 0;
        is_carry_ct = false;
    }
    else
    {
        auto &cc = cfhe_base->GetBinFHEContext();
        sum = cc.EvalNOT(a);
        carry_out_ct = COPY_CT(a);
        is_carry_ct = true;
    }
}

void AEGateLogic::HalfSubtractor(ConstLWECiphertext &a, ConstLWECiphertext &b,
                                 LWECiphertext &sum, LWECiphertext &carry_out)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    sum = cc.EvalBinGate(XOR, a, b);
    carry_out = cc.EvalBinGate(OR, a, cc.EvalNOT(b));
}

void AEGateLogic::HalfSubtractor(const LWEPlaintext &a, ConstLWECiphertext &b, LWECiphertext &sum, LWECiphertext &carry_out_ct, LWEPlaintext &carry_out_pt, bool &is_carry_ct)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    LWECiphertext not_b = cc.EvalNOT(b);
    if (a == 0)
    {
        sum = COPY_CT(b);
        carry_out_ct = not_b;
        is_carry_ct = true;
    }
    else
    {
        sum = not_b;
        carry_out_pt = 1;
        is_carry_ct = false;
    }
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

void AEGateLogic::FullAdder(ConstLWECiphertext &a, const LWEPlaintext &b, const LWEPlaintext &c,
                            LWECiphertext &sum, LWECiphertext &carry_out_ct,
                            LWEPlaintext &carry_out_pt, bool &is_carry_ct)
{
    if (b == c)
    {
        sum = COPY_CT(a);
        carry_out_pt = b;
        is_carry_ct = false;
    }
    else
    {
        auto &cc = cfhe_base->GetBinFHEContext();
        sum = cc.EvalNOT(a);
        carry_out_ct = COPY_CT(a);
        is_carry_ct = true;
    }
}

void AEGateLogic::FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, const LWEPlaintext &c, LWECiphertext &sum, LWECiphertext &carry_out)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    if (c == 0)
    {
        sum = cc.EvalBinGate(XOR, a, b);
        carry_out = cc.EvalBinGate(AND, a, b);
    }
    else
    {
        sum = cc.EvalBinGate(XNOR, a, b);
        carry_out = cc.EvalBinGate(OR, a, b);
    }
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

LWECiphertext AEGateLogic::DigitSum(ConstLWECiphertext &e1, ConstLWECiphertext &e0, ConstLWECiphertext &s0)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    LWECiphertext t = cc.EvalBinGate(AND, e0, cc.EvalNOT(s0));
    LWECiphertext s1 = cc.EvalBinGate(XOR, e1, t);
    return s1;
}

CFixedPoint AEGateLogic::Add_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b,
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
            out[0] = cc.EvalBinGate(XOR, a[0], b[0]);
        }
        else if (i == 0 && !carry_in)
        {
            HalfAdder(a[0], b[0], out[0], carry);
        }
        else if (i == n_digit - 1 && !carry_out)
        {
            out[i] = XOR3(a[i], b[i], carry);
        }
        else
        {
            FullAdder(a[i], b[i], carry, out[i], carry);
        }
    }
    return out;
}

CFixedPoint AEGateLogic::Sub_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b,
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
            out[0] = cc.EvalBinGate(XOR, a[0], b[0]);
        }
        else if (i == 0 && !carry_in)
        {
            HalfSubtractor(a[0], b[0], out[0], carry);
        }
        else if (i == n_digit - 1 && !carry_out)
        {
            out[i] = XOR3(a[i], cc.EvalNOT(b[i]), carry);
        }
        else
        {
            FullAdder(a[i], cc.EvalNOT(b[i]), carry, out[i], carry);
        }
    }
    return out;
}

CFixedPoint AEGateLogic::Add_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b,
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
        else if (i == 0 && !carry_in)
        {
            HalfAdder(a[0], b[0], out[0], carry, carry_pt, is_lastcarry_ct);
        }
        else if (i == n_digit - 1 && !carry_out)
        {
            if (is_lastcarry_ct)
            {
                out[i] = cc.EvalBinGate(b[i] ? XNOR : XOR, a[i], carry);
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
        else if (is_lastcarry_ct)
        {
            FullAdder(a[i], carry, b[i], out[i], carry);
        }
        else
        {
            FullAdder(a[i], b[i], carry_pt, out[i], carry, carry_pt, is_lastcarry_ct);
        }
    }
    return out;
}

CFixedPoint AEGateLogic::Sub_PtCt_FixedPoint(const PFixedPoint &a, const CFixedPoint &b,
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
            out[0] = PXOR(b[0], a[0]);
        }
        else if (i == 0 && !carry_in)
        {
            HalfSubtractor(a[0], b[0], out[0], carry, carry_pt, is_lastcarry_ct);
        }
        else if (i == n_digit - 1 && !carry_out)
        {
            if (is_lastcarry_ct)
            {
                out[i] = cc.EvalBinGate(a[i] ? XOR : XNOR, b[i], carry);
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
        else if (is_lastcarry_ct)
        {
            FullAdder(cc.EvalNOT(b[i]), carry, a[i], out[i], carry);
        }
        else
        {
            FullAdder(cc.EvalNOT(b[i]), a[i], carry_pt, out[i], carry, carry_pt, is_lastcarry_ct);
        }
    }
    return out;
}

CFixedPoint AEGateLogic::Neg(const CFixedPoint &a)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
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

LWECiphertext AEGateLogic::CmpNotEq(const CFixedPoint &a, const CFixedPoint &b)
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

LWECiphertext AEGateLogic::CmpEq(const CFixedPoint &a, const CFixedPoint &b)
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

LWECiphertext AEGateLogic::CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b)
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

LWECiphertext AEGateLogic::CmpGT_U(const CFixedPoint &a, const CFixedPoint &b)
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

LWECiphertext AEGateLogic::CmpGTEq_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U(b, a);
}

LWECiphertext AEGateLogic::CmpLT_U(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U(b, a);
}

LWECiphertext AEGateLogic::CmpLTEq(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext AEGateLogic::CmpGT(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGT_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext AEGateLogic::CmpGTEq(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpGTEq_U(ToggleMSB(a), ToggleMSB(b));
}

LWECiphertext AEGateLogic::CmpLT(const CFixedPoint &a, const CFixedPoint &b)
{
    return CmpLT_U(ToggleMSB(a), ToggleMSB(b));
}

CFixedPoint AEGateLogic::FullMul(const CFixedPoint &a, const CFixedPoint &b)
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
            LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
            if (i == 0)
            {
                HalfAdder(out[i + j], p, out[i + j], carry);
            }
            else if (i < n_digit - 1)
            {
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            }
            else if (j == 1)
            {
                HalfAdder(p, carry, out[i + j], out[i + j + 1]);
            }
            else
            {
                FullAdder(out[i + j], p, carry, out[i + j], out[i + j + 1]);
            }
        }
    }
    return out;
}

CFixedPoint AEGateLogic::FullMul(const CFixedPoint &a, const PFixedPoint &b)
{
    CFixedPoint out, acc;
    uint num_zeros = 0;
    if (a.size() == 0 || b.size() == 0)
    {
        out.push_back(GetConstantFalse());
        return out;
    }
    for (uint8_t i = 0; i < b.size(); i++)
    {
        if (b[i] == 0)
        {
            if (acc.size() == 0)
            {
                num_zeros++;
            }
            else
            {
                out.push_back(COPY_CT(acc.front()));
                acc.erase(acc.begin());
            }
        }
        else if (acc.size() == 0)
        {
            for (uint8_t j = 0; j < num_zeros; j++)
            {
                out.push_back(GetConstantFalse());
            }
            num_zeros = 0;
            out.push_back(COPY_CT(a[0]));
            for (uint8_t j = 1; j < a.size(); j++)
            {
                acc.push_back(a[j]);
            }
        }
        else
        {
            size_t s = acc.size();
            acc = Add(acc, CFixedPoint(a.begin(), a.begin() + s));
            SetIsLastCarryCT(true);
            out.push_back(COPY_CT(acc.front()));
            acc.erase(acc.begin());
            if (a.size() > s)
            {
                CFixedPoint sum = AddC(CFixedPoint(a.begin() + s, a.end()), PFixedPoint(a.size() - s, 0));
                for (size_t j = 0; j < sum.size(); j++)
                {
                    acc.push_back(sum[j]);
                }
            }
            acc.push_back(COPY_CT(carry));
        }
    }
    for (size_t j = 0; j < acc.size(); j++)
    {
        out.push_back(COPY_CT(acc[j]));
    }
    if (out.size() == 0)
    {
        out.push_back(GetConstantFalse());
    }
    return out;
}

CFixedPoint AEGateLogic::FullMulFast(const CFixedPoint &a, const PFixedPoint &b)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    if (a.size() == 0 || b.size() == 0 || cfhe_base->PFixedPoint2uint(b) == 0)
    {
        CFixedPoint zero(1);
        zero[0] = GetConstantFalse();
        return zero;
    }
    size_t out_n_bits = 0;
    if (Get_PtFullMul_Cost(b, a.size(), out_n_bits) <= Get_Pt2sCompFullMul_Cost(b, a.size()))
    {
        return FullMul(a, b);
    }
    PFixedPoint b_neg = BaseArithmeticsEngine::Neg(b);
    CFixedPoint res_neg = FullMul(a, b_neg);
    CFixedPoint out_lo, out_mid, out_hi;
    if (res_neg.size() <= b.size())
    {
        out_lo = Sub(PFixedPoint(res_neg.size(), 0), res_neg);
        for (uint8_t i = 0; i < b.size() - res_neg.size(); i++)
        {
            out_mid.push_back(cc.EvalNOT(carry));
        }
        out_hi = SubCNC(a, PFixedPoint(a.size(), 0));
    }
    else
    {
        out_lo = Sub(PFixedPoint(b.size(), 0), CFixedPoint(res_neg.begin(), res_neg.begin() + b.size()));
        out_mid = SubC(CFixedPoint(a.begin(), a.begin() + (res_neg.size() - b.size())), CFixedPoint(res_neg.begin() + b.size(), res_neg.end()));
        if (a.size() > res_neg.size() - b.size())
        {
            out_hi = SubCNC(CFixedPoint(a.begin() + (res_neg.size() - b.size()), a.end()), PFixedPoint(a.size() - (res_neg.size() - b.size()), 0));
        }
    }
    CFixedPoint out(out_lo.size() + out_mid.size() + out_hi.size());
    for (uint8_t i = 0; i < out_lo.size(); i++)
    {
        out[i] = out_lo[i];
    }
    for (uint8_t i = 0; i < out_mid.size(); i++)
    {
        out[i + out_lo.size()] = out_mid[i];
    }
    for (uint8_t i = 0; i < out_hi.size(); i++)
    {
        out[i + out_lo.size() + out_mid.size()] = out_hi[i];
    }
    return out;
}

CFixedPoint AEGateLogic::BoothsMul(const CFixedPoint &a, const PFixedPoint &b)
{
    if (a.size() == 0 || b.size() == 0 || cfhe_base->PFixedPoint2uint(b) == 0)
    {
        CFixedPoint zero(1);
        zero[0] = GetConstantFalse();
        return zero;
    }
    CFixedPoint aa = a;
    aa.push_back(a.back()); // The most negative number correction
    CFixedPoint acc(aa.size());
    CFixedPoint buffer;
    for (size_t i = 0; i < acc.size(); i++)
    {
        acc[i] = GetConstantFalse();
    }
    for (size_t i = 0; i < b.size(); i++)
    {
        uint k = (b[i] << 1) + ((i > 0) ? b[i - 1] : 0);
        switch (k)
        {
        case 1:
            acc = AddNC(acc, aa);
            break;
        case 2:
            acc = SubNC(acc, aa);
            break;
        default:
            break;
        }
        buffer.push_back(acc[0]);
        for (size_t j = 1; j < acc.size(); j++)
        {
            acc[j - 1] = (j == acc.size() - 1) ? COPY_CT(acc[j]) : acc[j];
        }
    }
    buffer.insert(buffer.end(), acc.begin(), acc.end() - 1);
    return buffer;
}

CFixedPoint AEGateLogic::Mul(const CFixedPoint &a, const CFixedPoint &b)
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
            LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
            if (i == 0 && j < n_digit - 1)
            {
                HalfAdder(out[i + j], p, out[i + j], carry);
            }
            else if (i < n_digit - j - 1)
            {
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            }
            else if (j < n_digit - 1)
            {
                out[i + j] = cc.EvalBinGate(XOR, out[i + j], carry);
                out[i + j] = cc.EvalBinGate(XOR, out[i + j], p);
            }
            else
            {
                out[i + j] = cc.EvalBinGate(XOR, out[i + j], p);
            }
        }
    }
    return out;
}

uint AEGateLogic::Get_CtCtAdd_Cost(size_t n_bits)
{
    return (n_bits > 0) ? 5 * n_bits - 3 : 0;
}

uint AEGateLogic::Get_CtCtSubC_Cost(size_t n_bits)
{
    return (n_bits > 0) ? 5 * n_bits : 0;
}

uint AEGateLogic::Get_CtPtAddC_Cost(size_t n_bits)
{
    return (n_bits > 0) ? 2 * n_bits : 0;
}

uint AEGateLogic::Get_PtCtSub_Cost(size_t n_bits)
{
    return (n_bits > 0) ? 2 * n_bits - 2 : 0;
}

uint AEGateLogic::Get_CtPtSubCNC_Cost(size_t n_bits)
{
    return (n_bits > 0) ? 2 * n_bits - 1 : 0;
}

uint AEGateLogic::Get_PtFullMul_Cost(const PFixedPoint &pt, size_t ct_n_bits, size_t &out_n_bits)
{
    uint cost = 0;
    size_t num_carry = 0;
    size_t r = 1;
    size_t start = 0;
    out_n_bits = 1;
    for (start = 0; start < pt.size(); start++)
    {
        if (pt[start] == 0)
        {
            continue;
        }
        else
        {
            out_n_bits = start + ct_n_bits;
            start++;
            break;
        }
    }
    for (size_t i = start; i < pt.size(); i++)
    {
        if (pt[i] == 0)
        {
            r++;
            continue;
        }
        else if (r >= ct_n_bits + num_carry)
        {
            out_n_bits = i + ct_n_bits;
            num_carry = 0;
            r = 1;
        }
        else
        {
            out_n_bits = i + ct_n_bits + 1;
            cost += Get_CtCtAdd_Cost(ct_n_bits + num_carry - r);
            cost += Get_CtPtAddC_Cost(r - num_carry);
            num_carry = 1;
            r = 1;
        }
    }
    return cost;
}

uint AEGateLogic::Get_Pt2sCompFullMul_Cost(const PFixedPoint &pt, size_t ct_n_bits)
{
    size_t out_n_bits = 0;
    size_t pt_n_bits = pt.size();
    uint cost = Get_PtFullMul_Cost(BaseArithmeticsEngine::Neg(pt), ct_n_bits, out_n_bits);
    if (out_n_bits <= pt_n_bits)
    {
        cost += Get_PtCtSub_Cost(out_n_bits);
        cost += Get_CtPtSubCNC_Cost(ct_n_bits);
    }
    else
    {
        cost += Get_PtCtSub_Cost(pt_n_bits);
        cost += Get_CtCtSubC_Cost(out_n_bits - pt_n_bits);
        cost += Get_CtPtSubCNC_Cost(ct_n_bits - out_n_bits + pt_n_bits);
    }

    return cost;
}
