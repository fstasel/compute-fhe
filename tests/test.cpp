#include "include/CFHE_Test.h"

using namespace computefhe_test;

int main() {
    // CFHE_Test::TestAll();
    // CFHE_Test::TestAllNoise();

    CFHE_Test t(CCPARAM_TOY, ALU_GATELOGIC, true);
    t.SetNumTest(10);
    t.SetVerbosity(4);
    t.Test(TestType::TT_PADD);
    t.Test(TestType::TT_PADDC);
    t.Test(TestType::TT_PADD_NC);

    return 0;
}