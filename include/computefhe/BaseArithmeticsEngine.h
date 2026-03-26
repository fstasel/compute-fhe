#pragma once

#include <computefhe/ComputeFHE.h>

using namespace lbcrypto;

namespace computefhe {

    class BaseArithmeticsEngine {
      protected:
        LWECiphertext carry;
        ComputeFHE *cfhe_base;

      public:
        BaseArithmeticsEngine(ComputeFHE *cfhe);
        virtual ~BaseArithmeticsEngine();

        LWECiphertext GetCarry();
        void SetCarry(LWECiphertext value);
        void SetCarry();
        void ResetCarry();
        LWECiphertext GetConstantFalse();
        LWECiphertext GetConstantTrue();

        virtual LWECiphertext Gate_AND(ConstLWECiphertext &a,
                                       ConstLWECiphertext &b);
        virtual LWECiphertext Gate_NAND(ConstLWECiphertext &a,
                                        ConstLWECiphertext &b);
        virtual LWECiphertext Gate_OR(ConstLWECiphertext &a,
                                      ConstLWECiphertext &b);
        virtual LWECiphertext Gate_NOR(ConstLWECiphertext &a,
                                       ConstLWECiphertext &b);
        virtual LWECiphertext Gate_XOR(ConstLWECiphertext &a,
                                       ConstLWECiphertext &b);
        virtual LWECiphertext Gate_XNOR(ConstLWECiphertext &a,
                                        ConstLWECiphertext &b);
        virtual LWECiphertext Gate_NOT(ConstLWECiphertext &a);

        virtual void HalfAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                               LWECiphertext &sum,
                               LWECiphertext &carry_out) = 0;
        virtual void HalfSubtractor(ConstLWECiphertext &a,
                                    ConstLWECiphertext &b, LWECiphertext &sum,
                                    LWECiphertext &carry_out) = 0;
        virtual void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                               ConstLWECiphertext &c, LWECiphertext &sum,
                               LWECiphertext &carry_out) = 0;
        virtual LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b,
                                   ConstLWECiphertext &c) = 0;
        virtual LWECiphertext MulAdd(ConstLWECiphertext &m,
                                     ConstLWECiphertext &a,
                                     ConstLWECiphertext &b,
                                     LWECiphertext *carry_out = nullptr) = 0;
        virtual FixedPoint Add(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint AddC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint AddNC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint Sub(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint SubC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint SubNC(const FixedPoint &a, const FixedPoint &b) = 0;
        virtual FixedPoint Neg(const FixedPoint &a) = 0;
        virtual LWECiphertext CmpNotEq(const FixedPoint &a,
                                       const FixedPoint &b) = 0;
        virtual LWECiphertext CmpEq(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        virtual LWECiphertext CmpLTEq_U(const FixedPoint &a,
                                        const FixedPoint &b) = 0;
        virtual LWECiphertext CmpGT_U(const FixedPoint &a,
                                      const FixedPoint &b) = 0;
        virtual LWECiphertext CmpGTEq_U(const FixedPoint &a,
                                        const FixedPoint &b) = 0;
        virtual LWECiphertext CmpLT_U(const FixedPoint &a,
                                      const FixedPoint &b) = 0;
        virtual LWECiphertext CmpLTEq(const FixedPoint &a,
                                      const FixedPoint &b) = 0;
        virtual LWECiphertext CmpGT(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        virtual LWECiphertext CmpGTEq(const FixedPoint &a,
                                      const FixedPoint &b) = 0;
        virtual LWECiphertext CmpLT(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        virtual FixedPoint FullMul(const FixedPoint &a,
                                   const FixedPoint &b) = 0;
        virtual FixedPoint Mul(const FixedPoint &a, const FixedPoint &b) = 0;

        FixedPoint ToggleMSB(const FixedPoint &a);
        virtual LWECiphertext Mux(LWECiphertext s, LWECiphertext a,
                                  LWECiphertext b) = 0;
        virtual FixedPoint Mux(LWECiphertext s, const FixedPoint a,
                               const FixedPoint b);
    };
} // namespace computefhe