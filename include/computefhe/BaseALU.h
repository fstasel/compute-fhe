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

        // FHE-Level operations
        virtual BinaryDigit FHE_False();
        virtual BinaryDigit FHE_True();
        virtual BinaryDigit FHE_AND(const BinaryDigit &a, const BinaryDigit &b);
        virtual BinaryDigit FHE_NAND(const BinaryDigit &a,
                                     const BinaryDigit &b);
        virtual BinaryDigit FHE_OR(const BinaryDigit &a, const BinaryDigit &b);
        virtual BinaryDigit FHE_NOR(const BinaryDigit &a, const BinaryDigit &b);
        virtual BinaryDigit FHE_XOR(const BinaryDigit &a, const BinaryDigit &b);
        virtual BinaryDigit FHE_XNOR(const BinaryDigit &a,
                                     const BinaryDigit &b);
        virtual BinaryDigit FHE_NOT(const BinaryDigit &a);
        virtual BinaryDigit FHE_MUX(const BinaryDigit &s, const BinaryDigit &a,
                                    const BinaryDigit &b);

        // Base Logic Gates
        virtual BinaryDigit Constant0();
        virtual BinaryDigit Constant1();
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
        virtual BinaryDigit Gate_MUX(const BinaryDigit &s, const BinaryDigit &a,
                                     const BinaryDigit &b);

        // Abstract gates
        virtual BinaryDigit Gate_MAJ(const BinaryDigit &a, const BinaryDigit &b,
                                     const BinaryDigit &c) = 0;
        virtual BinaryDigit Gate_XOR3(const BinaryDigit &a,
                                      const BinaryDigit &b,
                                      const BinaryDigit &c) = 0;
        virtual BinaryDigit Gate_MulAdd(const BinaryDigit &m,
                                        const BinaryDigit &a,
                                        const BinaryDigit &b,
                                        BinaryDigit *carry_out = nullptr) = 0;
        virtual BinaryDigit Gate_DigitSum(const BinaryDigit &e1,
                                          const BinaryDigit &e0,
                                          const BinaryDigit &s0) = 0;

        // Interface
        virtual FixedPoint Mux(const BinaryDigit &s, const FixedPoint &a,
                               const FixedPoint &b) = 0;

        virtual FixedPoint ToggleMSB(const FixedPoint &a) = 0;

        virtual FixedPoint ShiftLeft(const FixedPoint &a, size_t shift) = 0;
        virtual FixedPoint ShiftRight(const FixedPoint &a, size_t shift,
                                      bool is_arithmetic = false) = 0;

        virtual void Swap_if(const BinaryDigit &cond, BinaryDigit &a,
                             BinaryDigit &b) = 0;
        virtual void Swap_if(const BinaryDigit &cond, FixedPoint &a,
                             FixedPoint &b) = 0;

        virtual void HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                               BinaryDigit &sum, BinaryDigit &carry_out) = 0;
        virtual void HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                                    BinaryDigit &sum,
                                    BinaryDigit &carry_out) = 0;
        virtual void FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c, BinaryDigit &sum,
                               BinaryDigit &carry_out) = 0;

        virtual FixedPoint Add(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint AddC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint AddNC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint AddCNC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint Sub(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint SubC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint SubNC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint SubCNC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint Neg(const FixedPoint &a) = 0;
        virtual FixedPoint Not(const FixedPoint &a) = 0;
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
        virtual void DivU(const FixedPoint &a, const FixedPoint &b,
                          FixedPoint &q, FixedPoint &r) = 0;

        virtual FixedPoint PAdd(const FixedPoint &a, const FixedPoint &pb) = 0;
        virtual FixedPoint PAddC(const FixedPoint &a, const FixedPoint &pb) = 0;
        virtual FixedPoint PAddNC(const FixedPoint &a,
                                  const FixedPoint &pb) = 0;
        virtual FixedPoint PAddCNC(const FixedPoint &a,
                                   const FixedPoint &pb) = 0;
        virtual FixedPoint PSub(const FixedPoint &pa, const FixedPoint &b) = 0;
        virtual FixedPoint PSubC(const FixedPoint &pa, const FixedPoint &b) = 0;
        virtual FixedPoint PSubNC(const FixedPoint &pa,
                                  const FixedPoint &b) = 0;
        virtual FixedPoint PSubCNC(const FixedPoint &pa,
                                   const FixedPoint &b) = 0;
        virtual FixedPoint CPSub(const FixedPoint &a, const FixedPoint &pb) = 0;
        virtual FixedPoint CPSubC(const FixedPoint &a,
                                  const FixedPoint &pb) = 0;
        virtual FixedPoint CPSubNC(const FixedPoint &a,
                                   const FixedPoint &pb) = 0;
        virtual FixedPoint CPSubCNC(const FixedPoint &a,
                                    const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpNotEq(const FixedPoint &a,
                                      const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpEq(const FixedPoint &a,
                                   const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpLTEq_U(const FixedPoint &a,
                                       const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpGT_U(const FixedPoint &a,
                                     const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpGTEq_U(const FixedPoint &a,
                                       const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpLT_U(const FixedPoint &a,
                                     const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpLTEq(const FixedPoint &a,
                                     const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpGT(const FixedPoint &a,
                                   const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpGTEq(const FixedPoint &a,
                                     const FixedPoint &pb) = 0;
        virtual BinaryDigit PCmpLT(const FixedPoint &a,
                                   const FixedPoint &pb) = 0;
    };
} // namespace computefhe