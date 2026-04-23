#pragma once
#include <computefhe/BaseALU.h>

namespace computefhe {

    class ALUGateLogic : virtual public BaseALU {
      public:
        ALUGateLogic(ComputeFHE *cfhe);

        // Logic Gates
        virtual BinaryDigit Gate_MAJ(const BinaryDigit &a, const BinaryDigit &b,
                                     const BinaryDigit &c);
        virtual BinaryDigit Gate_XOR3(const BinaryDigit &a,
                                      const BinaryDigit &b,
                                      const BinaryDigit &c);
        virtual BinaryDigit Gate_MulAdd(const BinaryDigit &m,
                                        const BinaryDigit &a,
                                        const BinaryDigit &b,
                                        BinaryDigit *carry_out = nullptr);
        virtual BinaryDigit Gate_DigitSum(const BinaryDigit &e1,
                                          const BinaryDigit &e0,
                                          const BinaryDigit &s0);

        // Interface
        virtual FixedPoint Mux(const BinaryDigit &s, const FixedPoint &a,
                               const FixedPoint &b);
        virtual FixedPoint ToggleMSB(const FixedPoint &a);

        virtual FixedPoint ShiftLeft(const FixedPoint &a, size_t shift);
        virtual FixedPoint ShiftRight(const FixedPoint &a, size_t shift,
                                      bool is_arithmetic = false);

        virtual void Swap_if(const BinaryDigit &cond, BinaryDigit &a,
                             BinaryDigit &b);
        virtual void Swap_if(const BinaryDigit &cond, FixedPoint &a,
                             FixedPoint &b);

        virtual void HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                               BinaryDigit &sum, BinaryDigit &carry_out);
        virtual void HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                                    BinaryDigit &sum, BinaryDigit &carry_out);
        virtual void FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c, BinaryDigit &sum,
                               BinaryDigit &carry_out);

        virtual FixedPoint Add(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint AddC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint AddNC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint AddCNC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint Sub(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint SubC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint SubNC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint Neg(const FixedPoint &a);
        virtual BinaryDigit CmpNotEq(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpEq(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpLTEq_U(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpGT_U(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpGTEq_U(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpLT_U(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpLTEq(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpGT(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpGTEq(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpLT(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint FullMul(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint Mul(const FixedPoint &a, const FixedPoint &b);
        virtual void DivU(const FixedPoint &a, const FixedPoint &b,
                          FixedPoint &q, FixedPoint &r);

        virtual FixedPoint PAdd(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PAddC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PAddNC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PAddCNC(const FixedPoint &a, const FixedPoint &pb);
    };
} // namespace computefhe