#pragma once
#include <computefhe/BaseALU.h>

namespace computefhe {

    class ALUGateLogic : public BaseALU {
      public:
        ALUGateLogic(ComputeFHE *cfhe);

        void HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                       BinaryDigit &sum, BinaryDigit &carry_out);
        void HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                            BinaryDigit &sum, BinaryDigit &carry_out);
        void FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                       const BinaryDigit &c, BinaryDigit &sum,
                       BinaryDigit &carry_out);
        BinaryDigit XOR3(const BinaryDigit &a, const BinaryDigit &b,
                         const BinaryDigit &c);
        BinaryDigit MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                           const BinaryDigit &b,
                           BinaryDigit *carry_out = nullptr);
        FixedPoint Add(const FixedPoint &a, const FixedPoint &b);
        FixedPoint AddC(const FixedPoint &a, const FixedPoint &b);
        FixedPoint AddNC(const FixedPoint &a, const FixedPoint &b);
        FixedPoint Sub(const FixedPoint &a, const FixedPoint &b);
        FixedPoint SubC(const FixedPoint &a, const FixedPoint &b);
        FixedPoint SubNC(const FixedPoint &a, const FixedPoint &b);
        FixedPoint Neg(const FixedPoint &a);
        BinaryDigit CmpNotEq(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpEq(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpLTEq_U(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpGT_U(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpGTEq_U(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpLT_U(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpLTEq(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpGT(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpGTEq(const FixedPoint &a, const FixedPoint &b);
        BinaryDigit CmpLT(const FixedPoint &a, const FixedPoint &b);
        FixedPoint FullMul(const FixedPoint &a, const FixedPoint &b);
        FixedPoint Mul(const FixedPoint &a, const FixedPoint &b);
        void DivU(const FixedPoint &a, const FixedPoint &b, FixedPoint &q,
                  FixedPoint &r);
        BinaryDigit Mux(BinaryDigit s, BinaryDigit a, BinaryDigit b);
        void Swap_if(const BinaryDigit cond, BinaryDigit &a, BinaryDigit &b);
    };
} // namespace computefhe