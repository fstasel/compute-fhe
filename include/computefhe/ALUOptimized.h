#pragma once

#include <computefhe/ALUStandard.h>

namespace computefhe {

    class ALUOptimized : virtual public ALUStandard {
      public:
        ALUOptimized(ComputeFHE *cfhe);

        // FHE-Level operations
        virtual BinaryDigit FHE_MAJ(const BinaryDigit &a, const BinaryDigit &b,
                                    const BinaryDigit &c);
        virtual BinaryDigit FHE_XOR3(const BinaryDigit &a, const BinaryDigit &b,
                                     const BinaryDigit &c);
        virtual BinaryDigit FHE_MulAdd(const BinaryDigit &m,
                                       const BinaryDigit &a,
                                       const BinaryDigit &b,
                                       BinaryDigit *carry_out = nullptr);
        virtual BinaryDigit FHE_MUX(const BinaryDigit &s, const BinaryDigit &a,
                                    const BinaryDigit &b);
        virtual BinaryDigit FHE_DigitSum(const BinaryDigit &e1,
                                         const BinaryDigit &e0,
                                         const BinaryDigit &s0);

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
        virtual void FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c, BinaryDigit &sum,
                               BinaryDigit &carry_out);
        virtual BinaryDigit CmpLTEq_U(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpGT_U(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint FullMul(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint Mul(const FixedPoint &a, const FixedPoint &b);
        virtual void Swap_if(const BinaryDigit &cond, BinaryDigit &a,
                             BinaryDigit &b);

        virtual FixedPoint PAdd(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PAddC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PAddNC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PAddCNC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PSub(const FixedPoint &pa, const FixedPoint &b);
        virtual FixedPoint PSubC(const FixedPoint &pa, const FixedPoint &b);
        virtual FixedPoint PSubNC(const FixedPoint &pa, const FixedPoint &b);
        virtual FixedPoint PSubCNC(const FixedPoint &pa, const FixedPoint &b);
        virtual FixedPoint Neg(const FixedPoint &a);
    };
} // namespace computefhe