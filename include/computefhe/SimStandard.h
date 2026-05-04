/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

/**
 * @file SimStandard.h
 * @brief Simulator implementation for standard ALU operations.
 */

#pragma once
#include <computefhe/ALUStandard.h>
#include <computefhe/BaseALUSimulator.h>

namespace computefhe {
    /**
     * @class SimStandard
     * @brief Simulator implementation for standard ALU operations.
     *
     * Tracks statistics and simulates the behavior of the ALUStandard class.
     */
    class SimStandard : virtual public BaseALUSimulator,
                        virtual public ALUStandard {
      public:
        SimStandard(ComputeFHE *cfhe);
    };
} // namespace computefhe
