#include <computefhe/SimGateLogic.h>
#include <computefhe/AEGateLogic.h>
using namespace computefhe;

SimGateLogic::SimGateLogic(ComputeFHE *cfhe) : BaseAESimulator(cfhe)
{
}

void SimGateLogic::HalfAdder()
{
    num_xorxnor++;
    num_andor++;
    num_bs += 2;
}

void SimGateLogic::HalfAdder(const LWEPlaintext &b, LWEPlaintext &carry_out_pt, bool &is_carry_ct)
{
    if (b == 0)
    {
        carry_out_pt = 0;
        is_carry_ct = false;
    }
    else
    {
        num_not++;
        is_carry_ct = true;
    }
}

void SimGateLogic::HalfSubtractor()
{
    num_xorxnor++;
    num_andor++;
    num_not++;
    num_bs += 2;
}

void SimGateLogic::HalfSubtractor(const LWEPlaintext &a, LWEPlaintext &carry_out_pt, bool &is_carry_ct)
{
    num_not++;
    if (a == 0)
    {
        is_carry_ct = true;
    }
    else
    {
        carry_out_pt = 1;
        is_carry_ct = false;
    }
}

void SimGateLogic::FullAdder()
{
    num_xorxnor += 2;
    num_andor += 3;
    num_bs += 5;
}

void SimGateLogic::FullAdder(const LWEPlaintext &b, const LWEPlaintext &c, LWEPlaintext &carry_out_pt, bool &is_carry_ct)
{
    if (b == c)
    {
        carry_out_pt = b;
        is_carry_ct = false;
    }
    else
    {
        num_not++;
        is_carry_ct = true;
    }
}

void SimGateLogic::FullAdder(const LWEPlaintext &c)
{
    num_xorxnor++;
    num_andor++;
    num_bs += 2;
}

void SimGateLogic::XOR3()
{
    num_xorxnor += 2;
    num_bs += 2;
}

void SimGateLogic::MulAdd(bool carry_out)
{
    if (carry_out)
    {
        num_andor += 2;
        num_xorxnor++;
        num_bs += 3;
    }
    else
    {
        num_andor++;
        num_xorxnor++;
        num_bs += 2;
    }
}

void SimGateLogic::DigitSum()
{
    num_not++;
    num_andor++;
    num_xorxnor++;
    num_bs += 2;
}

size_t SimGateLogic::Add_CtCt_FixedPoint(const size_t n_bits, const bool &carry_in, const bool &carry_out)
{
    for (size_t i = 0; i < n_bits; i++)
    {
        if (n_bits == 1 && !carry_in && !carry_out)
        {
            num_xorxnor++;
            num_bs++;
        }
        else if (i == 0 && !carry_in)
        {
            HalfAdder();
        }
        else if (i == n_bits - 1 && !carry_out)
        {
            XOR3();
        }
        else
        {
            FullAdder();
        }
    }
    return n_bits;
}

size_t SimGateLogic::Sub_CtCt_FixedPoint(const size_t n_bits, const bool &carry_in, const bool &carry_out)
{
    for (size_t i = 0; i < n_bits; i++)
    {
        if (n_bits == 1 && !carry_in && !carry_out)
        {
            num_xorxnor++;
            num_bs++;
        }
        else if (i == 0 && !carry_in)
        {
            HalfSubtractor();
        }
        else if (i == n_bits - 1 && !carry_out)
        {
            num_not++;
            XOR3();
        }
        else
        {
            num_not++;
            FullAdder();
        }
    }
    return n_bits;
}

size_t SimGateLogic::Add_CtPt_FixedPoint(const PFixedPoint &b, const bool &carry_in, const bool &carry_out)
{
    size_t n_digit = b.size();

    for (size_t i = 0; i < n_digit; i++)
    {
        if (n_digit == 1 && !carry_in && !carry_out)
        {
            PXOR(dummy_ct, b[0]);
        }
        else if (i == 0 && !carry_in)
        {
            HalfAdder(b[0], carry_pt, is_lastcarry_ct);
        }
        else if (i == n_digit - 1 && !carry_out)
        {
            if (is_lastcarry_ct)
            {
                num_xorxnor++;
                num_bs++;
            }
            else if (b[i] == carry_pt)
            {
                // do nothing
            }
            else
            {
                num_not++;
            }
        }
        else if (is_lastcarry_ct)
        {
            FullAdder(b[i]);
        }
        else
        {
            FullAdder(b[i], carry_pt, carry_pt, is_lastcarry_ct);
        }
    }
    return n_digit;
}

size_t SimGateLogic::Sub_PtCt_FixedPoint(const PFixedPoint &a, const bool &carry_in, const bool &carry_out)
{
    size_t n_digit = a.size();

    for (size_t i = 0; i < n_digit; i++)
    {
        if (n_digit == 1 && !carry_in && !carry_out)
        {
            PXOR(dummy_ct, a[0]);
        }
        else if (i == 0 && !carry_in)
        {
            HalfSubtractor(a[0], carry_pt, is_lastcarry_ct);
        }
        else if (i == n_digit - 1 && !carry_out)
        {
            if (is_lastcarry_ct)
            {
                num_xorxnor++;
                num_bs++;
            }
            else if (a[i] != carry_pt)
            {
                // do nothing
            }
            else
            {
                num_not++;
            }
        }
        else if (is_lastcarry_ct)
        {
            num_not++;
            FullAdder(a[i]);
        }
        else
        {
            num_not++;
            FullAdder(a[i], carry_pt, carry_pt, is_lastcarry_ct);
        }
    }
    return n_digit;
}

size_t SimGateLogic::Neg_Ct_FixedPoint(const size_t n_bits)
{
    num_not++;
    for (size_t i = 1; i < n_bits; i++)
    {
        num_not++;
        if (i < n_bits - 1)
        {
            HalfAdder();
        }
        else
        {
            num_xorxnor++;
            num_bs++;
        }
    }
    return n_bits;
}

void SimGateLogic::CmpNotEq_CtCt_FixedPoint(const size_t n_bits)
{
    num_xorxnor++;
    num_bs++;
    for (size_t i = 1; i < n_bits; i++)
    {
        num_xorxnor++;
        num_andor++;
        num_bs += 2;
    }
}

void SimGateLogic::CmpEq_CtCt_FixedPoint(const size_t n_bits)
{
    num_xorxnor++;
    num_bs++;
    for (size_t i = 1; i < n_bits; i++)
    {
        num_xorxnor++;
        num_andor++;
        num_bs += 2;
    }
}

void SimGateLogic::CmpLTEq_U_CtCt_FixedPoint(const size_t n_bits)
{
    num_not++;
    num_andor++;
    num_bs++;
    for (size_t i = 1; i < n_bits; i++)
    {
        num_not++;
        num_andor += 4;
        num_bs += 4;
    }
}

void SimGateLogic::CmpGT_U_CtCt_FixedPoint(const size_t n_bits)
{
    num_not++;
    num_andor++;
    num_bs++;
    for (size_t i = 1; i < n_bits; i++)
    {
        num_not++;
        num_andor += 4;
        num_bs += 4;
    }
}

void SimGateLogic::CmpNotEq_CtPt_FixedPoint(const PFixedPoint &b)
{
    PXOR(dummy_ct, b[0]);
    for (size_t i = 1; i < b.size(); i++)
    {
        PXOR(dummy_ct, b[i]);
        num_andor++;
        num_bs++;
    }
}

void SimGateLogic::CmpEq_CtPt_FixedPoint(const PFixedPoint &b)
{

    PXNOR(dummy_ct, b[0]);
    for (size_t i = 1; i < b.size(); i++)
    {
        PXNOR(dummy_ct, b[i]);
        num_andor++;
        num_bs++;
    }
}

void SimGateLogic::CmpLTEq_U_CtPt_FixedPoint(const PFixedPoint &b)
{
    bool flag = false;
    for (size_t i = 0; i < b.size(); i++)
    {
        if (flag || (!flag && b[i] == 0))
        {
            if (!flag)
            {
                num_not++;
                flag = true;
            }
            else if (b[i] == 0)
            {
                num_not++;
                num_andor++;
                num_bs++;
            }
            else
            {
                num_not++;
                num_andor++;
                num_bs++;
            }
        }
    }
}

void SimGateLogic::CmpGT_U_CtPt_FixedPoint(const PFixedPoint &b)
{
    bool flag = false;
    for (size_t i = 0; i < b.size(); i++)
    {
        if (flag || (!flag && b[i] == 0))
        {
            if (!flag)
            {
                flag = true;
            }
            else if (b[i] == 0)
            {
                num_andor++;
                num_bs++;
            }
            else
            {
                num_andor++;
                num_bs++;
            }
        }
    }
}

size_t SimGateLogic::FullMul_CtCt_FixedPoint(const size_t n_bits)
{
    size_t n_digit = n_bits;

    size_t out_bits = (n_digit == 1) ? 1 : (n_digit << 1);
    for (size_t i = 0; i < n_digit; i++)
    {
        num_andor++;
        num_bs++;
    }
    for (size_t j = 1; j < n_digit; j++)
    {
        for (size_t i = 0; i < n_digit; i++)
        {
            num_andor++;
            num_bs++;
            if (i == 0)
            {
                HalfAdder();
            }
            else if (i < n_digit - 1)
            {
                FullAdder();
            }
            else if (j == 1)
            {
                HalfAdder();
            }
            else
            {
                FullAdder();
            }
        }
    }
    return out_bits;
}

size_t SimGateLogic::FullMul_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b)
{
    size_t out_bits = 0, acc_bits = 0;
    uint num_zeros = 0;
    if (n_bits == 0 || b.size() == 0)
    {
        return 1;
    }
    for (size_t i = 0; i < b.size(); i++)
    {
        if (b[i] == 0)
        {
            if (acc_bits == 0)
            {
                num_zeros++;
            }
            else
            {
                out_bits++;
                acc_bits--;
            }
        }
        else if (acc_bits == 0)
        {
            out_bits += num_zeros + 1;
            num_zeros = 0;
            acc_bits = n_bits - 1;
        }
        else
        {
            size_t s = acc_bits;
            acc_bits = SimAdd(s);
            SetIsLastCarryCT(true);
            out_bits++;
            acc_bits--;
            if (n_bits > s)
            {
                size_t sum_bits = SimAddC(PFixedPoint(n_bits - s, 0));
                acc_bits += sum_bits;
            }
            acc_bits++;
        }
    }
    out_bits += acc_bits;
    if (out_bits == 0)
    {
        out_bits = 1;
    }
    return out_bits;
}

size_t SimGateLogic::FullMulFast_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b)
{
    AEGateLogic *ae = (AEGateLogic *)cfhe_base->GetArithmeticsEngine();
    if (n_bits == 0 || b.size() == 0 || cfhe_base->PFixedPoint2uint(b) == 0)
    {
        return 1;
    }
    size_t out_n_bits = 0;
    if (ae->Get_PtFullMul_Cost(b, n_bits, out_n_bits) <= ae->Get_Pt2sCompFullMul_Cost(b, n_bits))
    {
        return FullMul_CtPt_FixedPoint(n_bits, b);
    }
    PFixedPoint b_neg = BaseArithmeticsEngine::Neg(b);
    size_t res_neg_bits = SimFullMul(n_bits, b_neg);
    size_t out_lo_bits = 0, out_mid_bits = 0, out_hi_bits = 0;
    if (res_neg_bits <= b.size())
    {
        out_lo_bits = SimSub(PFixedPoint(res_neg_bits, 0));
        for (size_t i = 0; i < b.size() - res_neg_bits; i++)
        {
            num_not++;
            out_mid_bits++;
        }
        out_hi_bits = SimSubCNC(0, PFixedPoint(n_bits, 0));
    }
    else
    {
        out_lo_bits = SimSub(PFixedPoint(b.size(), 0));
        out_mid_bits = SimSubC(res_neg_bits - b.size());
        if (n_bits > res_neg_bits - b.size())
        {
            out_hi_bits = SimSubCNC(PFixedPoint(n_bits - (res_neg_bits - b.size()), 0));
        }
    }
    size_t out_bits = out_lo_bits + out_mid_bits + out_hi_bits;
    return out_bits;
}

size_t SimGateLogic::BoothsMul_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b)
{
    if (n_bits == 0 || b.size() == 0 || cfhe_base->PFixedPoint2uint(b) == 0)
    {
        return 1;
    }
    size_t acc_bits = n_bits + 1;
    size_t buffer_bits = 0;
    for (size_t i = 0; i < b.size(); i++)
    {
        uint k = (b[i] << 1) + ((i > 0) ? b[i - 1] : 0);
        switch (k)
        {
        case 1:
            acc_bits = SimAddNC(acc_bits);
            break;
        case 2:
            acc_bits = SimSubNC(acc_bits);
            break;
        default:
            break;
        }
        buffer_bits++;
    }
    buffer_bits += acc_bits - 1;
    return buffer_bits;
}

size_t SimGateLogic::Mul_CtCt_FixedPoint(const size_t n_bits)
{
    size_t n_digit = n_bits;
    size_t out_bits = n_digit;
    for (size_t i = 0; i < n_digit; i++)
    {
        num_andor++;
        num_bs++;
    }
    for (size_t j = 1; j < n_digit; j++)
    {
        for (size_t i = 0; i < n_digit - j; i++)
        {
            num_andor++;
            num_bs++;
            if (i == 0 && j < n_digit - 1)
            {
                HalfAdder();
            }
            else if (i < n_digit - j - 1)
            {
                FullAdder();
            }
            else if (j < n_digit - 1)
            {
                num_xorxnor += 2;
                num_bs += 2;
            }
            else
            {
                num_xorxnor++;
                num_bs++;
            }
        }
    }
    return out_bits;
}

size_t SimGateLogic::Mul_CtPt_FixedPoint(const PFixedPoint &b)
{
    if (b.size() == 0 || cfhe_base->PFixedPoint2uint(b) == 0)
    {
        return 1;
    }
    size_t n_digit = b.size();
    size_t out_bits = n_digit;
    bool acc = false;
    for (size_t i = 0; i < n_digit; i++)
    {
        if (b[i] == 1 && !acc)
        {
            acc = true;
        }
        else if (b[i] == 1 && acc)
        {
            SimAddNC(n_digit - i);
        }
    }
    return out_bits;
}

size_t SimGateLogic::MulFast_CtPt_FixedPoint(const PFixedPoint &b)
{
    if (b.size() == 0 || cfhe_base->PFixedPoint2uint(b) == 0)
    {
        return 1;
    }
    AEGateLogic *ae = (AEGateLogic *)cfhe_base->GetArithmeticsEngine();
    if (ae->Get_PtMul_Cost(b) <= ae->Get_Pt2sCompMul_Cost(b))
    {
        return SimMul(b);
    }
    return SimNeg(SimMul(BaseArithmeticsEngine::Neg(b)));
}

void SimGateLogic::Mux_CCC()
{
    num_andor += 3;
    num_bs += 3;
}

void SimGateLogic::Mux_CCP(LWEPlaintext b)
{
    if (b == 1)
    {
        num_andor++;
        num_bs++;
        return;
    }
    num_not++;
    num_andor++;
    num_bs++;
}

void SimGateLogic::Mux_CPP(LWEPlaintext a, LWEPlaintext b, LWEPlaintext &out_pt, bool &is_out_ct)
{
    if (a == b)
    {
        out_pt = a;
        is_out_ct = false;
        return;
    }
    is_out_ct = true;
    if (b == 0)
    {
        num_not++;
    }
}
