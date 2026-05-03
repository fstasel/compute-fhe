#include <computefhe/ComputeFHE.h>
using namespace computefhe;
using namespace std;

int main() {
    // initialize with toy security and optimized ALU logic
    Init(CCPARAM_TOY, ALU_OPTIMIZED, true);

    // encrypt some values
    Euint8 a = 42;
    Euint8 b = 10;

    // perform homomorphic addition
    Euint8 sum = a + b;

    // use encrypted conditional branching
    Eif(sum > 50) { sum -= 5; }
    else {
        sum += 5;
    }

    // decrypt and print
    // (conversion to primitive types triggers decryption)
    cout << "Result: " << (uint32_t)sum << endl;

    // terminate cfhe-context
    Finalize();

    return 0;
}