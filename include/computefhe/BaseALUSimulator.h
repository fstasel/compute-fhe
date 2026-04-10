#pragma once

#include <computefhe/BaseALU.h>
#include <computefhe/FixedPoint.h>

using namespace lbcrypto;

namespace computefhe {
    class ComputeFHE;

    class BaseALUSimulator : public BaseALU {
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

        void PrintStats();
        void ResetStats();

        uint GetNumBS();

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
    };
} // namespace computefhe