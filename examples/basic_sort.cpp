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

int main() {
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, true, SIMULATOR_MODE);

    cfhe_base->setAutoEncryptMode(true);           // Auto-encrypt data
    Evector<Eint8> arr = {8, 7, 6, 5, 4, 3, 2, 1}; // Encrypted input
    cfhe_base->setAutoEncryptMode(false); // Back to server-side behavior

    cout << "In: " << arr << endl;
    cout << "Basic Encrypted Sort:" << endl;
    basic_encrypted_sort(arr);
    cout << "Out: " << arr << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
        cfhe_base->GetSimulator()->ResetStats();
    }

    cfhe_base->setAutoEncryptMode(true);  // Auto-encrypt data
    arr = {8, 7, 6, 5, 4, 3, 2, 1};       // Encrypted input
    cfhe_base->setAutoEncryptMode(false); // Back to server-side behavior

    cout << "In: " << arr << endl;
    cout << "Basic Encrypted Sort (Intrinsic):" << endl;
    basic_encrypted_sort_intrinsic(arr);
    cout << "Out: " << arr << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
    }

    computefhe::Finalize();
    return 0;
}