#include <computefhe/ComputeFHE.h>
#include <iostream>

using namespace computefhe;
using namespace std;

#define SIMULATOR_MODE 1

// Binary restoring square root algorithm
template <typename T> T isqrt(T N) {
    size_t out_sz = N.getSize() >> 1;
    Einteger x(out_sz, false);
    T s = 0, sn, diff;
    int msb = out_sz - 1;
    for (int k = msb; k >= 0; --k) {
        uint64_t delta = (1ULL << k);
        diff = ((T)x << (k + 1)) + (1ULL << (2 * k));
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