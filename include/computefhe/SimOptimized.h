#pragma once

#include <computefhe/ALUOptimized.h>
#include <computefhe/SimGateLogic.h>

namespace computefhe {

    class SimOptimized : public SimGateLogic, public ALUOptimized {
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
    };
} // namespace computefhe