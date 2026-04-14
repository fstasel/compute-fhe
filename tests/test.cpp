#include "include/CFHE_Test.h"

using namespace computefhe_test;

int main() {
    // CFHE_Test::TestAll();
    // CFHE_Test::TestAllNoise();
    CFHE_Test cfhe_test(CryptoContextParam::CCPARAM_TOY, ALUType::ALU_OPTIMIZED,
                        true);
    cfhe_test.SetRegenerateKeys(false);
    cfhe_test.SetNumTest(1);
    cfhe_test.SetVerbosity(4);
    cfhe_test.Test(TestType::TT_FULLMUL, 8);

    return 0;
}