#pragma once

#include <computefhe/ALUGateLogic.h>

namespace computefhe {

    class ALUOptimized : public ALUGateLogic {
      public:
        ALUOptimized(ComputeFHE *cfhe);

        void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                       ConstLWECiphertext &c, LWECiphertext &sum,
                       LWECiphertext &carry_out);
        LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b,
                           ConstLWECiphertext &c);
        LWECiphertext MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a,
                             ConstLWECiphertext &b,
                             LWECiphertext *carry_out = nullptr);
        LWECiphertext CmpLTEq_U(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext CmpGT_U(const FixedPoint &a, const FixedPoint &b);
        FixedPoint FullMul(const FixedPoint &a, const FixedPoint &b);
        FixedPoint Mul(const FixedPoint &a, const FixedPoint &b);
        LWECiphertext Mux(LWECiphertext s, LWECiphertext a, LWECiphertext b);
    };
} // namespace computefhe