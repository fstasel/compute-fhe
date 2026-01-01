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

CFixedPoint AEGateLogic::Add(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    HalfAdder(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        FullAdder(a[i], b[i], carry, out[i], carry);
    }
    return out;
}

CFixedPoint AEGateLogic::Add(const CFixedPoint &a, const PFixedPoint &b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    HalfAdder(a[0], b[0], out[0], carry, carry_pt, is_lastcarry_ct);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        if (is_lastcarry_ct)
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

CFixedPoint AEGateLogic::AddC(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        FullAdder(a[i], b[i], carry, out[i], carry);
    }
    return out;
}

CFixedPoint AEGateLogic::AddC(const CFixedPoint &a, const PFixedPoint &b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        if (is_lastcarry_ct)
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

CFixedPoint AEGateLogic::AddNC(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
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

CFixedPoint AEGateLogic::AddNC(const CFixedPoint &a, const PFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    HalfAdder(a[0], b[0], out[0], carry, carry_pt, is_lastcarry_ct);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        if (i < n_digit - 1)
        {
            if (is_lastcarry_ct)
            {
                FullAdder(a[i], carry, b[i], out[i], carry);
            }
            else
            {
                FullAdder(a[i], b[i], carry_pt, out[i], carry, carry_pt, is_lastcarry_ct);
            }
        }
        else
        {
            if (is_lastcarry_ct)
            {
                out[i] = cc.EvalBinGate(b[i] ? XNOR : XOR, a[i], carry);
            }
            else
            {
                if (b[i] == carry_pt)
                {
                    out[i] = COPY_CT(a[i]);
                }
                else
                {
                    out[i] = cc.EvalNOT(a[i]);
                }
            }
        }
    }
    return out;
}

CFixedPoint AEGateLogic::Sub(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    HalfSubtractor(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        LWECiphertext inv_b = cc.EvalNOT(b[i]);
        FullAdder(a[i], inv_b, carry, out[i], carry);
    }
    return out;
}

CFixedPoint AEGateLogic::Sub(const CFixedPoint &a, const PFixedPoint &b)
{
    return Add(a, BaseArithmeticsEngine::Neg(b));
}

CFixedPoint AEGateLogic::Sub(const PFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    HalfSubtractor(a[0], b[0], out[0], carry, carry_pt, is_lastcarry_ct);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        if (is_lastcarry_ct)
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

CFixedPoint AEGateLogic::SubC(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        LWECiphertext inv = cc.EvalNOT(b[i]);
        FullAdder(a[i], inv, carry, out[i], carry);
    }
    return out;
}

CFixedPoint AEGateLogic::SubC(const CFixedPoint &a, const PFixedPoint &b)
{
    return AddC(a, BaseArithmeticsEngine::Not(b));
}

CFixedPoint AEGateLogic::SubC(const PFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++)
    {
        if (is_lastcarry_ct)
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

CFixedPoint AEGateLogic::SubNC(const CFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
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

CFixedPoint AEGateLogic::SubNC(const CFixedPoint &a, const PFixedPoint &b)
{
    return AddNC(a, BaseArithmeticsEngine::Neg(b));
}

CFixedPoint AEGateLogic::SubNC(const PFixedPoint &a, const CFixedPoint &b)
{
    assert(a.size() == b.size());
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    CFixedPoint out(n_digit);
    HalfSubtractor(a[0], b[0], out[0], carry, carry_pt, is_lastcarry_ct);
    for (uint8_t i = 1; i < n_digit; i++)
    {
        if (i < n_digit - 1)
        {
            if (is_lastcarry_ct)
            {
                FullAdder(cc.EvalNOT(b[i]), carry, a[i], out[i], carry);
            }
            else
            {
                FullAdder(cc.EvalNOT(b[i]), a[i], carry_pt, out[i], carry, carry_pt, is_lastcarry_ct);
            }
        }
        else
        {
            if (is_lastcarry_ct)
            {
                out[i] = cc.EvalBinGate(a[i] ? XOR : XNOR, b[i], carry);
            }
            else
            {
                if (a[i] != carry_pt)
                {
                    out[i] = COPY_CT(b[i]);
                }
                else
                {
                    out[i] = cc.EvalNOT(b[i]);
                }
            }
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
    cout << "Size of FullMul result: " << out.size() << endl;
    return out;
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

uint AEGateLogic::Get_CtPtAddC_Cost(size_t n_bits)
{
    return (n_bits > 0) ? 2 * n_bits : 0;
}

uint AEGateLogic::Get_PtCtSub_Cost(size_t n_bits)
{
    return (n_bits > 0) ? 2 * n_bits - 2 : 0;
}

uint AEGateLogic::Get_CtPtSubC_Cost(size_t n_bits)
{
    return Get_CtPtAddC_Cost(n_bits);
}

uint AEGateLogic::Get_PtFullMul_Cost(const PFixedPoint &pt, size_t ct_n_bits)
{
    uint cost = 0;
    size_t num_carry = 0;
    size_t r = 1;
    size_t start = 0;
    for (start = 0; start < pt.size(); start++)
    {
        if (pt[start] == 0)
        {
            continue;
        }
        else
        {
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
            num_carry = 0;
            r = 1;
        }
        else
        {
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
    return Get_PtFullMul_Cost(BaseArithmeticsEngine::Neg(pt), ct_n_bits) + Get_PtCtSub_Cost(pt.size()) + Get_CtPtSubC_Cost(pt.size());
}
