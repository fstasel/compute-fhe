#pragma once

#include "AEGateLogic.h"

class AEOptimized : public AEGateLogic
{
public:
    AEOptimized(ComputeFHE *cfhe);

    void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c,
                   LWECiphertext &sum, LWECiphertext &carry_out);
    LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c);
    LWECiphertext MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                         LWECiphertext *carry_out = nullptr);
    LWECiphertext DigitSum(ConstLWECiphertext &e1, ConstLWECiphertext &e0, ConstLWECiphertext &s0);

    // LWECiphertext CmpNotEq(const CFixedPoint &a, const CFixedPoint &b);
    // LWECiphertext CmpEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT_U(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint FullMul(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Mul(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Add(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint AddC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint AddNC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint Sub(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubC(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubNC(const PFixedPoint &a, const CFixedPoint &b);
};
