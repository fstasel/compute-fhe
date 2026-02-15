#include "SimOptimized.h"

SimOptimized::SimOptimized(ComputeFHE *cfhe) : SimGateLogic(cfhe)
{
}

void SimOptimized::FullAdder()
{
    XOR3();
    num_maj++;
    num_bs++;
}

void SimOptimized::XOR3()
{
    num_xor3++;
    num_bs++;
}

void SimOptimized::MulAdd(bool carry_out)
{
    if (carry_out)
    {
        num_mac++;
        num_bs += 2;
    }
    else
    {
        num_ma++;
        num_bs++;
    }
}

void SimOptimized::DigitSum()
{
    num_ds++;
    num_bs++;
}

void SimOptimized::CmpLTEq_U_CtCt_FixedPoint(const size_t n_bits)
{
    num_not += n_bits;
    num_andor++;
    num_maj += n_bits - 1;
    num_bs += n_bits;
}

void SimOptimized::CmpGT_U_CtCt_FixedPoint(const size_t n_bits)
{
    num_not += n_bits;
    num_andor++;
    num_maj += n_bits - 1;
    num_bs += n_bits;
}

size_t SimOptimized::FullMul_CtCt_FixedPoint(const size_t n_bits)
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
            if (i == 0)
            {
                MulAdd(true);
            }
            else if (i < n_digit - 1)
            {
                num_andor++;
                num_bs++;
                FullAdder();
            }
            else if (j == 1)
            {
                MulAdd(true);
            }
            else
            {
                num_andor++;
                num_bs++;
                FullAdder();
            }
        }
    }
    return out_bits;
}

size_t SimOptimized::Mul_CtCt_FixedPoint(const size_t n_bits)
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
            if (i == 0 && j < n_digit - 1)
            {
                MulAdd(true);
            }
            else if (i < n_digit - j - 1)
            {
                num_andor++;
                num_bs++;
                FullAdder();
            }
            else if (j < n_digit - 1)
            {
                num_andor++;
                num_bs++;
                XOR3();
            }
            else
            {
                MulAdd(false);
            }
        }
    }
    return out_bits;
}

size_t SimOptimized::Add_CtPt_FixedPoint(const PFixedPoint &b, const bool &carry_in, const bool &carry_out)
{
    size_t n_digit = b.size();

    for (size_t i = 0; i < n_digit; i++)
    {
        if (i == 0)
        {
            if (n_digit == 1 && !carry_in && !carry_out)
            {
                PXOR(dummy_ct, b[0]);
            }
            else if (!carry_in)
            {
                HalfAdder(b[0], carry_pt, is_lastcarry_ct);
            }
            else if (is_lastcarry_ct)
            {
                SimGateLogic::FullAdder(b[0]);
            }
            else
            {
                SimGateLogic::FullAdder(b[0], carry_pt, carry_pt, is_lastcarry_ct);
            }
        }
        else
        {
            if (is_lastcarry_ct)
            {
                PXOR(dummy_ct, b[i - 1]);
                PXOR(dummy_ct, b[i - 1]);
                PXOR(dummy_ct, b[i - 1]);
                DigitSum();
                PXOR(dummy_ct, b[i]);
                if (i == n_digit - 1 && carry_out)
                {
                    num_not++;
                    num_andor++;
                    num_bs++;
                }
            }
            else
            {
                SimGateLogic::FullAdder(b[i], carry_pt, carry_pt, is_lastcarry_ct);
            }
        }
    }
    return n_digit;
}

size_t SimOptimized::Sub_PtCt_FixedPoint(const PFixedPoint &a, const bool &carry_in, const bool &carry_out)
{
    size_t n_digit = a.size();

    for (size_t i = 0; i < n_digit; i++)
    {
        if (i == 0)
        {
            if (n_digit == 1 && !carry_in && !carry_out)
            {
                PXOR(dummy_ct, a[0]);
            }
            else if (!carry_in)
            {
                HalfSubtractor(a[0], carry_pt, is_lastcarry_ct);
            }
            else if (is_lastcarry_ct)
            {
                num_not++;
                SimGateLogic::FullAdder(a[0]);
            }
            else
            {
                num_not++;
                SimGateLogic::FullAdder(a[0], carry_pt, carry_pt, is_lastcarry_ct);
            }
        }
        else
        {
            if (is_lastcarry_ct)
            {
                PXNOR(dummy_ct, a[i - 1]);
                PXNOR(dummy_ct, a[i - 1]);
                PXOR(dummy_ct, a[i - 1]);
                DigitSum();
                PXOR(dummy_ct, a[i]);
                if (i == n_digit - 1 && carry_out)
                {
                    num_andor++;
                    num_bs++;
                }
            }
            else
            {
                num_not++;
                SimGateLogic::FullAdder(a[i], carry_pt, carry_pt, is_lastcarry_ct);
            }
        }
    }
    return n_digit;
}

size_t SimOptimized::Neg_Ct_FixedPoint(const size_t n_bits)
{
    return SimSubNC(PFixedPoint(n_bits, 0));
}

void SimOptimized::Mux_CCC()
{
    num_mux++;
    num_bs += 2;
}
