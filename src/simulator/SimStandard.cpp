#include <computefhe/SimStandard.h>
using namespace computefhe;

SimStandard::SimStandard(ComputeFHE *cfhe)
    : BaseALU(cfhe), BaseALUSimulator(cfhe), ALUStandard(cfhe) {}
