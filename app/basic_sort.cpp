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

int main() {
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, true, SIMULATOR_MODE);

    Evector<Eint8> arr = {8, 7, 6, 5, 4, 3, 2, 1};
    cout << arr << endl;

    basic_encrypted_sort(arr);
    cout << arr << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
    }

    computefhe::Finalize();
    return 0;
}