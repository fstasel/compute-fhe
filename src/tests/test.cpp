/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

#include "include/CFHE_Test.h"

using namespace computefhe_test;

int main() {

    CFHE_Test::TestAll();
    CFHE_Test::TestAllNoise();

    return 0;
}
