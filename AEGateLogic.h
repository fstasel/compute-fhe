#pragma once

#include "BaseArithmeticsEngine.h"

class AEGateLogic : public BaseArithmeticsEngine
{
public:
    AEGateLogic(ComputeFHE *cfhe);

    void HalfAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                   LWECiphertext &sum, LWECiphertext &carry_out);
    void HalfAdder(ConstLWECiphertext &a, const LWEPlaintext &b,
                   LWECiphertext &sum, LWECiphertext &carry_out_ct,
                   LWEPlaintext &carry_out_pt, bool &is_carry_ct);

    void HalfSubtractor(ConstLWECiphertext &a, ConstLWECiphertext &b,
                        LWECiphertext &sum, LWECiphertext &carry_out);
    void HalfSubtractor(const LWEPlaintext &a, ConstLWECiphertext &b,
                        LWECiphertext &sum, LWECiphertext &carry_out_ct,
                        LWEPlaintext &carry_out_pt, bool &is_carry_ct);

    void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c,
                   LWECiphertext &sum, LWECiphertext &carry_out);
    void FullAdder(ConstLWECiphertext &a, const LWEPlaintext &b, const LWEPlaintext &c,
                   LWECiphertext &sum, LWECiphertext &carry_out_ct,
                   LWEPlaintext &carry_out_pt, bool &is_carry_ct);
    void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, const LWEPlaintext &c,
                   LWECiphertext &sum, LWECiphertext &carry_out);

    LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c);
    LWECiphertext MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                         LWECiphertext *carry_out = nullptr);
    LWECiphertext DigitSum(ConstLWECiphertext &e1, ConstLWECiphertext &e0, ConstLWECiphertext &s0);

    CFixedPoint Add(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Add(const CFixedPoint &a, const PFixedPoint &b);

    CFixedPoint AddC(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint AddC(const CFixedPoint &a, const PFixedPoint &b);

    CFixedPoint AddNC(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint AddNC(const CFixedPoint &a, const PFixedPoint &b);

    CFixedPoint Sub(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Sub(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint Sub(const PFixedPoint &a, const CFixedPoint &b);

    CFixedPoint SubC(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint SubC(const PFixedPoint &a, const CFixedPoint &b);

    CFixedPoint SubNC(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubNC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint SubNC(const PFixedPoint &a, const CFixedPoint &b);

    CFixedPoint Neg(const CFixedPoint &a);
    LWECiphertext CmpNotEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLT_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLTEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGTEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLT(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint FullMul(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Mul(const CFixedPoint &a, const CFixedPoint &b);
};
