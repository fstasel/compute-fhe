#pragma once
#include <computefhe/BaseArithmeticsEngine.h>

namespace computefhe
{

    class AEGateLogic : public BaseArithmeticsEngine
    {
    public:
        AEGateLogic(ComputeFHE *cfhe);

        void HalfAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                       LWECiphertext &sum, LWECiphertext &carry_out);
        void HalfSubtractor(ConstLWECiphertext &a, ConstLWECiphertext &b,
                            LWECiphertext &sum, LWECiphertext &carry_out);
        void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c,
                       LWECiphertext &sum, LWECiphertext &carry_out);
        LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c);
        LWECiphertext MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                             LWECiphertext *carry_out = nullptr);
        FixedPoint Add(const FixedPoint &a, const FixedPoint &b);
        FixedPoint AddC(const FixedPoint &a, const FixedPoint &b);
        FixedPoint AddNC(const FixedPoint &a, const FixedPoint &b);
        FixedPoint Sub(const FixedPoint &a, const FixedPoint &b);
        FixedPoint SubC(const FixedPoint &a, const FixedPoint &b);
        FixedPoint SubNC(const FixedPoint &a, const FixedPoint &b);
        FixedPoint Neg(const FixedPoint &a);
        LWECiphertext CmpNotEq(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpEq(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpLTEq_U(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpGT_U(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpGTEq_U(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpLT_U(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpLTEq(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpGT(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpGTEq(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpLT(const FixedPoint &a, const FixedPoint &b);
        FixedPoint FullMul(const FixedPoint &a, const FixedPoint &b);
        FixedPoint Mul(const FixedPoint &a, const FixedPoint &b);
    };
}