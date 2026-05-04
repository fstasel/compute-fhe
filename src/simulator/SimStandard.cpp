/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

#include <computefhe/SimStandard.h>
using namespace computefhe;

SimStandard::SimStandard(ComputeFHE *cfhe)
    : BaseALU(cfhe), BaseALUSimulator(cfhe), ALUStandard(cfhe) {}
