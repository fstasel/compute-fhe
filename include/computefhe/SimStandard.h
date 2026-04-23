#pragma once
#include <computefhe/ALUStandard.h>
#include <computefhe/BaseALUSimulator.h>

namespace computefhe {
    class SimStandard : virtual public BaseALUSimulator,
                        virtual public ALUStandard {
      public:
        SimStandard(ComputeFHE *cfhe);
    };
} // namespace computefhe