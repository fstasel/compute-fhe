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
    // LWECiphertext CmpNotEq(const FixedPoint &a, const FixedPoint &b);
    // LWECiphertext CmpEq(const FixedPoint &a, const FixedPoint &b);
    LWECiphertext CmpLTEq_U(const FixedPoint &a, const FixedPoint &b);
    LWECiphertext CmpGT_U(const FixedPoint &a, const FixedPoint &b);
    FixedPoint FullMul(const FixedPoint &a, const FixedPoint &b);
    FixedPoint Mul(const FixedPoint &a, const FixedPoint &b);
};
