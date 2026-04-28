#pragma once

#include <computefhe/ALUOptimized.h>
#include <computefhe/SimStandard.h>

namespace computefhe {

    class SimOptimized : public SimStandard, public ALUOptimized {
      public:
        SimOptimized(ComputeFHE *cfhe);

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
    };
} // namespace computefhe
