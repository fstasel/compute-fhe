#pragma once
#include <computefhe/ALUGateLogic.h>
#include <computefhe/BaseALUSimulator.h>

namespace computefhe {
    class SimGateLogic : virtual public BaseALUSimulator,
                         virtual public ALUGateLogic {
      public:
        SimGateLogic(ComputeFHE *cfhe);
    };
} // namespace computefhe