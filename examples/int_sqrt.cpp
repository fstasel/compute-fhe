#include <computefhe/ComputeFHE.h>
#include <iostream>

using namespace computefhe;
using namespace std;

#define SIMULATOR_MODE 1

// Binary restoring square root algorithm
template <typename T> T isqrt(T N) {
    T x = 0;
    T s = 0, sn;
    int msb = (N.getSize() >> 1) - 1;
    for (int k = msb; k >= 0; --k) {
        uint64_t delta = (1ULL << k);
        T diff = (x << (k + 1)) + (1ULL << (2 * k));
        Ebool c = ((sn = s + diff) <= N);
        BinaryDigit c0 = c.getData()[0];
        T mask = Einteger(vector<BinaryDigit>(N.getSize(), c0), false);
        x += mask & delta;
        Eif(c) s = sn;
    }
    return x;
}

int main() {
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, true, SIMULATOR_MODE);

    Euint32 N = 4000000000U;
    cout << "N: " << N << endl;
    cout << "sqrt(N): " << isqrt(N) << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
    }

    computefhe::Finalize();
    return 0;
}