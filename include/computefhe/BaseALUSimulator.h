/**
 * @file BaseALUSimulator.h
 * @brief Defines the abstract base class for functional ALU simulators.
 */


#pragma once

#include <computefhe/BaseALU.h>
#include <computefhe/FixedPoint.h>

using namespace lbcrypto;

namespace computefhe {
    class ComputeFHE;

    /**
     * @class BaseALUSimulator
     * @brief Abstract base class for functional ALU simulators.
     *
     * Simulators allow for high-speed logic verification and the collection of
     * gate-level statistics without the computational cost of FHE operations.
     */
    class BaseALUSimulator : virtual public BaseALU {
      protected:
        uint num_bs = 0;
        uint num_not = 0;
        uint num_andor = 0;
        uint num_xorxnor = 0;
        uint num_xor3 = 0;
        uint num_maj = 0;
        uint num_ma = 0;
        uint num_mac = 0;
        uint num_ds = 0;
        uint num_mux = 0;

      public:
        BaseALUSimulator(ComputeFHE *cfhe);

        virtual void PrintStats();
        virtual void ResetStats();

        virtual uint GetNumBS();

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
    };
} // namespace computefhe