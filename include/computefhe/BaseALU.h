#pragma once

#include <computefhe/Einteger.h>
#include <computefhe/FixedPoint.h>

using namespace lbcrypto;

namespace computefhe {
    class ComputeFHE;

    /**
     * @class BaseALU
     * @brief Abstract base class for FHE-based Arithmetic Logic Units.
     *
     * This class defines the interface for all logic and arithmetic operations
     * performed on encrypted data (FixedPoint and BinaryDigit). It manages
     * internal state such as carry flags and provides gate-level operations.
     */
    class BaseALU {
      protected:
        BinaryDigit carry;
        ComputeFHE *cfhe_base;

      public:
        /**
         * @brief Construct a new BaseALU object.
         * @param cfhe Pointer to the ComputeFHE instance providing the crypto
         * context.
         */
        BaseALU(ComputeFHE *cfhe);

        /**
         * @brief Destroy the BaseALU object.
         */
        virtual ~BaseALU();

        /** @brief Returns the current internal carry state. */
        virtual BinaryDigit GetCarry();

        /** @brief Manually sets the internal carry to a specific value. */
        virtual void SetCarry(BinaryDigit value);

        /** @brief Sets the internal carry to an encrypted 'True' value. */
        virtual void SetCarry();

        /** @brief Resets the internal carry to an encrypted 'False' value. */
        virtual void ResetCarry();

        /** @name FHE-Level Gates
         * These methods provide logical abstractions.
         */
        ///@{
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
        ///@}

        /** @name Base Logic Gates
         * Fundamental cryptographic gate implementations.
         */
        ///@{

        /** @brief Returns encrypted constant 0 (false). */
        virtual BinaryDigit Constant0();
        /** @brief Returns encrypted constant 1 (true). */
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
        ///@}

        /** @name Abstract Specialized Gates
         * Pure virtual methods that must be implemented by optimized or
         * standard ALU logic.
         */
        ///@{
        /** @brief Majority gate: returns true if at least two inputs are true.
         */
        virtual BinaryDigit Gate_MAJ(const BinaryDigit &a, const BinaryDigit &b,
                                     const BinaryDigit &c) = 0;
        /** @brief 3-input XOR gate. */
        virtual BinaryDigit Gate_XOR3(const BinaryDigit &a,
                                      const BinaryDigit &b,
                                      const BinaryDigit &c) = 0;
        /** @brief Multiplies two digits and adds a third, optionally returning
         * carry out. */
        virtual BinaryDigit Gate_MulAdd(const BinaryDigit &m,
                                        const BinaryDigit &a,
                                        const BinaryDigit &b,
                                        BinaryDigit *carry_out = nullptr) = 0;
        /** @brief Performs bitwise digit summation logic. */
        virtual BinaryDigit Gate_DigitSum(const BinaryDigit &e1,
                                          const BinaryDigit &e0,
                                          const BinaryDigit &s0) = 0;
        ///@}

        /** @name Word-Level Interface
         * Operations acting on multi-bit FixedPoint objects.
         */
        ///@{

        /** @brief Multiplexer for FixedPoint values: returns 'a' if 's' is
         * true, else 'b'. */
        virtual FixedPoint Mux(const BinaryDigit &s, const FixedPoint &a,
                               const FixedPoint &b) = 0;

        /** @brief Toggles the Most Significant Bit (useful for sign
         * manipulation). */
        virtual FixedPoint ToggleMSB(const FixedPoint &a) = 0;

        /** @brief Logical shift left. */
        virtual FixedPoint ShiftLeft(const FixedPoint &a, size_t shift) = 0;
        /** @brief Shift right (supports both logical and arithmetic/signed
         * shifts). */
        virtual FixedPoint ShiftRight(const FixedPoint &a, size_t shift,
                                      bool is_arithmetic = false) = 0;

        /** @brief Conditional swap of two bits if 'cond' is true. */
        virtual void Swap_if(const BinaryDigit &cond, BinaryDigit &a,
                             BinaryDigit &b) = 0;
        /** @brief Conditional swap of two FixedPoint values if 'cond' is true.
         */
        virtual void Swap_if(const BinaryDigit &cond, FixedPoint &a,
                             FixedPoint &b) = 0;

        /** @brief 1-bit half adder. */
        virtual void HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                               BinaryDigit &sum, BinaryDigit &carry_out) = 0;
        /** @brief 1-bit half subtractor. */
        virtual void HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                                    BinaryDigit &sum,
                                    BinaryDigit &carry_out) = 0;
        /** @brief 1-bit full adder with explicit carry-in. */
        virtual void FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c, BinaryDigit &sum,
                               BinaryDigit &carry_out) = 0;
        ///@}

        /** @name Ciphertext-Ciphertext Arithmetic
         * Standard arithmetic between two encrypted FixedPoint values.
         */
        ///@{

        /** @brief Addition: result = a + b. */
        virtual FixedPoint Add(const FixedPoint &a, const FixedPoint &b) = 0;
        /** @brief Addition with Carry: result = a + b + carry. */
        virtual FixedPoint AddC(const FixedPoint &a, const FixedPoint &b) = 0;
        /** @brief Addition without updating internal carry. */
        virtual FixedPoint AddNC(const FixedPoint &a, const FixedPoint &b) = 0;
        /** @brief Addition with Carry, but without updating internal carry. */
        virtual FixedPoint AddCNC(const FixedPoint &a, const FixedPoint &b) = 0;

        /** @brief Subtraction: result = a - b. */
        virtual FixedPoint Sub(const FixedPoint &a, const FixedPoint &b) = 0;
        /** @brief Subtraction with Borrow (!Carry): result = a - b - !carry. */
        virtual FixedPoint SubC(const FixedPoint &a, const FixedPoint &b) = 0;
        /** @brief Subtraction without updating internal carry. */
        virtual FixedPoint SubNC(const FixedPoint &a, const FixedPoint &b) = 0;
        /** @brief Subtraction with Carry, but without updating internal carry.
         */
        virtual FixedPoint SubCNC(const FixedPoint &a, const FixedPoint &b) = 0;

        /** @brief Arithmetic negation: result = -a. */
        virtual FixedPoint Neg(const FixedPoint &a) = 0;
        /** @brief Bitwise NOT. */
        virtual FixedPoint Not(const FixedPoint &a) = 0;
        ///@}

        /** @name Comparisons
         * Logical comparisons returning encrypted boolean bits.
         */
        ///@{
        /** @brief Not-Equal. */
        virtual BinaryDigit CmpNotEq(const FixedPoint &a,
                                     const FixedPoint &b) = 0;
        /** @brief Equal. */
        virtual BinaryDigit CmpEq(const FixedPoint &a, const FixedPoint &b) = 0;
        /** @brief Unsigned Less-Than or Equal. */
        virtual BinaryDigit CmpLTEq_U(const FixedPoint &a,
                                      const FixedPoint &b) = 0;
        /** @brief Unsigned Greater-Than. */
        virtual BinaryDigit CmpGT_U(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        /** @brief Unsigned Greater-Than or Equal. */
        virtual BinaryDigit CmpGTEq_U(const FixedPoint &a,
                                      const FixedPoint &b) = 0;
        /** @brief Unsigned Less-Than. */
        virtual BinaryDigit CmpLT_U(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        /** @brief Signed Less-Than or Equal. */
        virtual BinaryDigit CmpLTEq(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        /** @brief Signed Greater-Than. */
        virtual BinaryDigit CmpGT(const FixedPoint &a, const FixedPoint &b) = 0;
        /** @brief Signed Greater-Than or Equal. */
        virtual BinaryDigit CmpGTEq(const FixedPoint &a,
                                    const FixedPoint &b) = 0;
        /** @brief Signed Less-Than. */
        virtual BinaryDigit CmpLT(const FixedPoint &a, const FixedPoint &b) = 0;
        ///@}

        /** @name Multi-Word Arithmetic
         * Complex arithmetic operations.
         */
        ///@{
        /** @brief Performs full multiplication resulting in potentially larger
         * bit-width. */
        virtual FixedPoint FullMul(const FixedPoint &a,
                                   const FixedPoint &b) = 0;
        /** @brief Standard multiplication (truncated to input width). */
        virtual FixedPoint Mul(const FixedPoint &a, const FixedPoint &b) = 0;
        /** @brief Unsigned division, calculating quotient (q) and remainder
         * (r). */
        virtual void DivU(const FixedPoint &a, const FixedPoint &b,
                          FixedPoint &q, FixedPoint &r) = 0;
        ///@}

        /** @name Ciphertext-Plaintext Arithmetic
         * Optimized operations where one operand is a known plaintext constant
         * (pb/pa).
         */
        ///@{

        /** @brief Plaintext addition: result = a + pb. */
        virtual FixedPoint PAdd(const FixedPoint &a, const FixedPoint &pb) = 0;
        /** @brief Plaintext addition with carry. */
        virtual FixedPoint PAddC(const FixedPoint &a, const FixedPoint &pb) = 0;
        /** @brief Plaintext addition without updating internal carry. */
        virtual FixedPoint PAddNC(const FixedPoint &a,
                                  const FixedPoint &pb) = 0;
        /** @brief Plaintext addition with carry, but no update to internal
         * state. */
        virtual FixedPoint PAddCNC(const FixedPoint &a,
                                   const FixedPoint &pb) = 0;

        /** @brief Plaintext subtraction: result = pa - b. */
        virtual FixedPoint PSub(const FixedPoint &pa, const FixedPoint &b) = 0;
        /** @brief Plaintext subtraction with carry. */
        virtual FixedPoint PSubC(const FixedPoint &pa, const FixedPoint &b) = 0;
        /** @brief Plaintext subtraction without updating internal carry. */
        virtual FixedPoint PSubNC(const FixedPoint &pa,
                                  const FixedPoint &b) = 0;
        /** @brief Plaintext subtraction with carry, but no update to internal
         * state. */
        virtual FixedPoint PSubCNC(const FixedPoint &pa,
                                   const FixedPoint &b) = 0;

        /** @brief Ciphertext-Plaintext subtraction: result = a - pb. */
        virtual FixedPoint CPSub(const FixedPoint &a, const FixedPoint &pb) = 0;
        /** @brief Ciphertext-Plaintext subtraction with carry. */
        virtual FixedPoint CPSubC(const FixedPoint &a,
                                  const FixedPoint &pb) = 0;
        /** @brief Ciphertext-Plaintext subtraction without updating internal
         * carry. */
        virtual FixedPoint CPSubNC(const FixedPoint &a,
                                   const FixedPoint &pb) = 0;
        /** @brief Ciphertext-Plaintext subtraction with carry, no update. */
        virtual FixedPoint CPSubCNC(const FixedPoint &a,
                                    const FixedPoint &pb) = 0;

        /** @brief Full multiplication by a plaintext constant. */
        virtual FixedPoint PFullMul(const FixedPoint &a,
                                    const FixedPoint &pb) = 0;
        /** @brief Optimized full multiplication by a plaintext constant. */
        virtual FixedPoint PFullMulFast(const FixedPoint &a,
                                        const FixedPoint &pb) = 0;
        /** @brief Multiplication using Booth's algorithm with a plaintext
         * constant. */
        virtual FixedPoint PBoothsMul(const FixedPoint &a,
                                      const FixedPoint &pb) = 0;
        /** @brief Standard multiplication by a plaintext constant. */
        virtual FixedPoint PMul(const FixedPoint &a, const FixedPoint &pb) = 0;
        /** @brief Optimized standard multiplication by a plaintext constant. */
        virtual FixedPoint PMulFast(const FixedPoint &a,
                                    const FixedPoint &pb) = 0;
        ///@}
    };
} // namespace computefhe