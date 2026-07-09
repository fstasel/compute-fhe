/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

/**
 * @file Serialize.h
 * @brief Serialization support for encrypted datatypes.
 */

#pragma once
#include <computefhe/ComputeFHE.h>
#include <openfhe/binfhe/binfhecontext-ser.h>

CEREAL_REGISTER_TYPE(computefhe::Einteger);
