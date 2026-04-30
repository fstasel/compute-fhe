#include <computefhe/ComputeFHE.h>
#include <iostream>

using namespace computefhe;
using namespace std;

#define SIMULATOR_MODE 1

template <typename T>
const Evector<Evector<T>> matrix_mul(const Evector<Evector<T>> &A,
                                     const Evector<Evector<T>> &B) {
    Evector<Evector<T>> C(A.size(), Evector<T>(B[0].size()));
    for (size_t i = 0; i < A.size(); i++) {
        for (size_t j = 0; j < B[0].size(); j++) {
            for (size_t k = 0; k < A[0].size(); k++) {
                C[i][j] += A[i][k] * B[k][j];
            }
        }
    }
    return C;
}

int main() {
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, true, SIMULATOR_MODE);

    cfhe_base->setAutoEncryptMode(true); // Auto-encrypt data
    Evector<Evector<Euint8>> A = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}}; // Encrypted
    Evector<Evector<Euint8>> B = {{1, 4, 9}, {2, 5, 8}, {3, 6, 9}}; // Encrypted
    cfhe_base->setAutoEncryptMode(false); // Back to server-side behavior
    Evector<Evector<Euint8>> C = {{1, 4, 9}, {2, 5, 8}, {3, 6, 9}}; // Plain

    cout << "Ciphertext A: " << A << endl;
    cout << "Ciphertext B: " << B << endl;
    cout << "Plaintext  C: " << C << endl;

    Evector<Evector<Euint8>> AB = matrix_mul(A, B);
    cout << "A * B: " << AB << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
        cfhe_base->GetSimulator()->ResetStats();
    }

    Evector<Evector<Euint8>> AC = matrix_mul(A, C);
    cout << "A * C: " << AC << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
    }

    computefhe::Finalize();
    return 0;
}