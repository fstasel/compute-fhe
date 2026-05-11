/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

/**
 * @file CFHETypes.h
 * @brief Defines core enumerations and helper functions for ComputeFHE
 * configuration.
 */

#pragma once

namespace computefhe {

    /**
     * @enum CryptoContextParam
     * @brief Supported cryptographic context parameters for OpenFHE.
     *
     * These values correspond to specific security levels and bootstrapping
     * configurations in OpenFHE.
     *
     * - **GINX**: Entries without 'LMKCDEY' use the GINX bootstrapping method
     *   (Gama-Izabachène-Nguyen-Xie).
     * - **LMKCDEY**: Refers to the bootstrapping scheme proposed by
     *   Lee-Micciancio-Kim-Choi-Deryabin-Eom-Yoo.
     * - **3-input logic**: Parameters ending in '_3' enable 3-input gate
     * optimizations.
     */
    enum CryptoContextParam {
        CCPARAM_STD128,
        CCPARAM_STD128_3,
        CCPARAM_STD128_LMKCDEY,
        CCPARAM_STD128_3_LMKCDEY,
        CCPARAM_STD192,
        CCPARAM_STD192_3,
        CCPARAM_STD192_LMKCDEY,
        CCPARAM_STD192_3_LMKCDEY,
        CCPARAM_STD256,
        CCPARAM_STD256_3,
        CCPARAM_STD256_LMKCDEY,
        CCPARAM_STD256_3_LMKCDEY,
        CCPARAM_TOY
    };

    /**
     * @brief Converts a CryptoContextParam value to a human-readable string.
     * @param v The cryptographic context parameter enum.
     * @return A string representation of the parameter set name.
     */
    inline const char *ToString(CryptoContextParam v) {
        switch (v) {
        case CCPARAM_STD128:
            return "STD128";
        case CCPARAM_STD128_3:
            return "STD128_3";
        case CCPARAM_STD128_LMKCDEY:
            return "STD128_LMKCDEY";
        case CCPARAM_STD128_3_LMKCDEY:
            return "STD128_3_LMKCDEY";
        case CCPARAM_STD192:
            return "STD192";
        case CCPARAM_STD192_3:
            return "STD192_3";
        case CCPARAM_STD192_LMKCDEY:
            return "STD192_LMKCDEY";
        case CCPARAM_STD192_3_LMKCDEY:
            return "STD192_3_LMKCDEY";
        case CCPARAM_STD256:
            return "STD256";
        case CCPARAM_STD256_3:
            return "STD256_3";
        case CCPARAM_STD256_LMKCDEY:
            return "STD256_LMKCDEY";
        case CCPARAM_STD256_3_LMKCDEY:
            return "STD256_3_LMKCDEY";
        case CCPARAM_TOY:
            return "TOY";
        default:
            return "[Unknown]";
        }
    }

    /**
     * @enum ALUType
     * @brief Specifies the logic gate implementation strategy.
     *
     * - ALU_STANDARD: Uses basic FHE gates for logic operations.
     * - ALU_OPTIMIZED: Uses specialized multi-input gates (like MAJ or XOR3)
     *   to reduce the number of bootstrapping operations.
     */
    enum ALUType { ALU_STANDARD, ALU_OPTIMIZED };

    /**
     * @brief Converts an ALUType value to a human-readable string.
     * @param v The ALU type enum.
     * @return A string representation ("STANDARD" or "OPTIMIZED").
     */
    inline const char *ToString(ALUType v) {
        switch (v) {
        case ALU_STANDARD:
            return "STANDARD";
        case ALU_OPTIMIZED:
            return "OPTIMIZED";
        default:
            return "[Unknown]";
        }
    }
} // namespace computefhe
