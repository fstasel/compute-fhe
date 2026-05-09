/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

#include <computefhe/ComputeFHE.h>
#include <iostream>
#include <vector>
#define SIMULATOR_MODE 1

using namespace computefhe;
using namespace std;
using Efp = EFix<32, 24, false>;

Efp calculate_average(Euint8 grades[], int size) {
    Efp average = 0.0;
    for (int i = 0; i < size; i++)
        average += (Efp)grades[i];

    return average / (double)size;
}

Efp find_max(Evector<Efp> averages) {
    Efp max = 0.0;
    for (auto &i : averages)
        Eif(i > max) max = i;

    return max;
}

int main() {
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, true, SIMULATOR_MODE);

    Euint8 grades[3][3] = {{15, 33, 28}, {25, 40, 39}, {5, 35, 43}};
    cfhe_base->setAutoEncryptMode(false);

    Evector<Efp> averages;
    for (int i = 0; i < 3; i++) {
        averages.push_back(calculate_average(grades[i], 3));
        cout << "Student " << (i + 1) << " average: " << averages[i] << endl;
    }

    Efp max_avg = find_max(averages);
    cout << "Highest average: " << max_avg << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
    }

    computefhe::Finalize();
    return 0;
}
