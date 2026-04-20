#include <computefhe/SimGateLogic.h>
using namespace computefhe;

SimGateLogic::SimGateLogic(ComputeFHE *cfhe)
    : BaseALU(cfhe), BaseALUSimulator(cfhe), ALUGateLogic(cfhe) {}
