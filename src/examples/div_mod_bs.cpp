/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

#include <computefhe/ComputeFHE.h>
using namespace computefhe;
using namespace std;

int main() {
    Init(CCPARAM_TOY, ALU_OPTIMIZED, true, true);

    Eint8 a = 42;
    Eint8 b = 10;
    cfhe_base->setAutoEncryptMode(false);

    Eint8 quo = a / b;
    cout << "Quotient: " << quo << endl;
    cfhe_base->GetSimulator()->PrintStats();
    cfhe_base->GetSimulator()->ResetStats();

    Eint8 rem = a % b;  // Uses the precomputed result of a / b.
    cout << "Remainder: " << rem << endl;
    cfhe_base->GetSimulator()->PrintStats();

    Finalize();

    return 0;
}
