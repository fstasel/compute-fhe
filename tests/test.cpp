#include "include/CFHE_Test.h"

using namespace computefhe_test;

int main() {
    // CFHE_Test::TestAll();
    // CFHE_Test::TestAllNoise();

    CFHE_Test t(CCPARAM_TOY, ALU_GATELOGIC, true);
    t.SetRegenerateKeys(false);
    t.SetNumTest(10);
    t.SetVerbosity(4);
    // t.Test(TestType::TT_PADD);
    // t.Test(TestType::TT_PADDC);
    // t.Test(TestType::TT_PADD_NC);
    // t.Test(TestType::TT_MUX);
    // t.Test(TestType::TT_PMUX);
    // t.Test(TestType::TT_PPMUX);
    t.Test(TestType::TT_ADDC_NC);

    return 0;
}