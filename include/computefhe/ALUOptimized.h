#pragma once

#include <computefhe/ALUGateLogic.h>

namespace computefhe {

    class ALUOptimized : public ALUGateLogic {
      public:
        ALUOptimized(ComputeFHE *cfhe);

        void FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                       const BinaryDigit &c, BinaryDigit &sum,
                       BinaryDigit &carry_out);
        BinaryDigit XOR3(const BinaryDigit &a, const BinaryDigit &b,
                         const BinaryDigit &c);
        BinaryDigit MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                           const BinaryDigit &b,
                           BinaryDigit *carry_out = nullptr);
        BinaryDigit CmpLTEq_U(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpGT_U(const FixedPoint &a, const FixedPoint &b);
        FixedPoint FullMul(const FixedPoint &a, const FixedPoint &b);
        FixedPoint Mul(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit Mux(BinaryDigit s, BinaryDigit a, BinaryDigit b);
    };
} // namespace computefhe