/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

#include <computefhe/ComputeFHE.h>
#include <iostream>

using namespace computefhe;
using namespace std;

#define SIMULATOR_MODE 1

void basic_encrypted_sort(Evector<Eint8> &arr) {
    for (uint i = 0; i < arr.size() - 1; i++) {
        for (uint j = i + 1; j < arr.size(); j++) {
            Eif(arr[i] > arr[j]) {
                Eint8 tmp = arr[i];
                arr[i] = arr[j];
                arr[j] = tmp;
            }
        }
    }
}

void basic_encrypted_sort_intrinsic(Evector<Eint8> &arr) {
    FixedPoint a, b;
    for (uint i = 0; i < arr.size() - 1; i++) {
        for (uint j = i + 1; j < arr.size(); j++) {
            cfhe_base->GetALU()->Swap_if((arr[i] > arr[j]).getData()[0],
                                         a = arr[i].getData(),
                                         b = arr[j].getData());
            arr[i] = Einteger(a, true);
            arr[j] = Einteger(b, true);
        }
    }
}

void batcher_odd_even_mergesort(Evector<Eint8> &arr) {
    FixedPoint a, b;
    size_t n = arr.size();
    for (size_t p = 1; p < n; p <<= 1) {
        for (size_t k = p; k >= 1; k >>= 1) {
            for (size_t j = k % p; j <= n - 1 - k; j += (k << 1)) {
                for (size_t i = 0; i <= std::min(k - 1, n - j - k - 1); i++) {
                    if ((i + j) / (p << 1) == (i + j + k) / (p << 1)) {
                        cfhe_base->GetALU()->Swap_if(
                            (arr[i + j] > arr[i + j + k]).getData()[0],
                            a = arr[i + j].getData(),
                            b = arr[i + j + k].getData());
                        arr[i + j] = Einteger(a, true);
                        arr[i + j + k] = Einteger(b, true);
                    }
                }
            }
        }
    }
}

int main() {
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, true, SIMULATOR_MODE);

    cfhe_base->setAutoEncryptMode(true); // Auto-encrypt data
    Evector<Eint8> arr = {16, 15, 14, 13, 12, 11, 10, 9,
                          8,  7,  6,  5,  4,  3,  2,  1}; // Encrypted input
    cfhe_base->setAutoEncryptMode(false); // Back to server-side behavior

    cout << "In: " << arr << endl;
    cout << "Basic Encrypted Sort:" << endl;
    basic_encrypted_sort(arr);
    cout << "Out: " << arr << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
        cfhe_base->GetSimulator()->ResetStats();
    }

    cfhe_base->setAutoEncryptMode(true); // Auto-encrypt data
    arr = {16, 15, 14, 13, 12, 11, 10, 9,
           8,  7,  6,  5,  4,  3,  2,  1}; // Encrypted input
    cfhe_base->setAutoEncryptMode(false);  // Back to server-side behavior

    cout << "In: " << arr << endl;
    cout << "Basic Encrypted Sort (Intrinsic):" << endl;
    basic_encrypted_sort_intrinsic(arr);
    cout << "Out: " << arr << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
        cfhe_base->GetSimulator()->ResetStats();
    }

    cfhe_base->setAutoEncryptMode(true); // Auto-encrypt data
    arr = {16, 15, 14, 13, 12, 11, 10, 9,
           8,  7,  6,  5,  4,  3,  2,  1}; // Encrypted input
    cfhe_base->setAutoEncryptMode(false);  // Back to server-side behavior

    cout << "In: " << arr << endl;
    cout << "Batcher odd-even mergesort:" << endl;
    batcher_odd_even_mergesort(arr);
    cout << "Out: " << arr << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
    }

    computefhe::Finalize();
    return 0;
}
