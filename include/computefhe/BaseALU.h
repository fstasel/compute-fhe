#pragma once

#include <computefhe/Einteger.h>
#include <computefhe/FixedPoint.h>

using namespace lbcrypto;

namespace computefhe {
    class ComputeFHE;
    class BaseALU {
      protected:
        BinaryDigit carry;
        ComputeFHE *cfhe_base;

      public:
        BaseALU(ComputeFHE *cfhe);
        virtual ~BaseALU();

        virtual BinaryDigit GetCarry();
        virtual void SetCarry(BinaryDigit value);
        virtual void SetCarry();
        virtual void ResetCarry();

        virtual BinaryDigit GetConstantFalse();
        virtual BinaryDigit GetConstantTrue();

        virtual BinaryDigit Gate_AND(const BinaryDigit &a,
                                     const BinaryDigit &b);
        virtual BinaryDigit Gate_NAND(const BinaryDigit &a,
                                      const BinaryDigit &b);
        virtual BinaryDigit Gate_OR(const BinaryDigit &a, const BinaryDigit &b);
        virtual BinaryDigit Gate_NOR(const BinaryDigit &a,
                                     const BinaryDigit &b);
        virtual BinaryDigit Gate_XOR(const BinaryDigit &a,
                                     const BinaryDigit &b);
        virtual BinaryDigit Gate_XNOR(const BinaryDigit &a,
                                      const BinaryDigit &b);
        virtual BinaryDigit Gate_NOT(const BinaryDigit &a);

        virtual FixedPoint ToggleMSB(const FixedPoint &a);

        virtual FixedPoint ShiftLeft(const FixedPoint &a, size_t shift);
        virtual FixedPoint ShiftRight(const FixedPoint &a, size_t shift,
                                      bool is_arithmetic = false);

        virtual FixedPoint Mux(BinaryDigit s, const FixedPoint a,
                               const FixedPoint b);
        virtual BinaryDigit Mux(BinaryDigit s, BinaryDigit a,
                                BinaryDigit b) = 0;

        virtual void Swap_if(const BinaryDigit cond, FixedPoint &a,
                             FixedPoint &b);
        virtual void Swap_if(const BinaryDigit cond, BinaryDigit &a,
                             BinaryDigit &b) = 0;

        virtual void HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                               BinaryDigit &sum, BinaryDigit &carry_out) = 0;
        virtual void HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                                    BinaryDigit &sum,
                                    BinaryDigit &carry_out) = 0;
        virtual void FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c, BinaryDigit &sum,
                               BinaryDigit &carry_out) = 0;
        virtual BinaryDigit XOR3(const BinaryDigit &a, const BinaryDigit &b,
                                 const BinaryDigit &c) = 0;
        virtual BinaryDigit MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                                   const BinaryDigit &b,
                                   BinaryDigit *carry_out = nullptr) = 0;
        virtual FixedPoint Add(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint AddC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint AddNC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint Sub(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint SubC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint SubNC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint Neg(const FixedPoint &a) = 0;
        virtual BinaryDigit CmpNotEq(const FixedPoint &a,
                                     const FixedPoint &b) = 0;
        virtual BinaryDigit CmpEq(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual BinaryDigit CmpLTEq_U(const FixedPoint &a,
                                      const FixedPoint &b) = 0;
        virtual BinaryDigit CmpGT_U(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        virtual BinaryDigit CmpGTEq_U(const FixedPoint &a,
                                      const FixedPoint &b) = 0;
        virtual BinaryDigit CmpLT_U(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        virtual BinaryDigit CmpLTEq(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        virtual BinaryDigit CmpGT(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual BinaryDigit CmpGTEq(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        virtual BinaryDigit CmpLT(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint FullMul(const FixedPoint &a,
                                   const FixedPoint &b) = 0;
        virtual FixedPoint Mul(const FixedPoint &a, const FixedPoint &b) = 0;
    };
} // namespace computefhe