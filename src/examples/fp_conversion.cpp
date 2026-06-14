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

    using fp8 = EFix<8, 4, true>;

    fp8 f = 2.5;
    Eint8 i = f.toInteger();
    fp8 f2 = f + (fp8)i;

    cout << "f: " << f << endl;
    cout << "i: " << i << endl;
    cout << "f2: " << f2 << endl;

    Finalize();

    return 0;
}
