#include "include/CFHE_Test.h"

using namespace computefhe_test;

int main() {
    // CFHE_Test::TestAll();
    // CFHE_Test::TestAllNoise();

    CFHE_Test t(CCPARAM_TOY, ALU_OPTIMIZED, true);
    t.SetRegenerateKeys(false);
    t.SetNumTest(10);
    t.SetVerbosity(0);
    t.Test(TestType::TT_PADD);
    t.Test(TestType::TT_PADDC);
    t.Test(TestType::TT_PADD_NC);
    t.Test(TestType::TT_PADDC_NC);
    t.Test(TestType::TT_PSUB);
    t.Test(TestType::TT_PSUBC);
    t.Test(TestType::TT_PSUB_NC);
    t.Test(TestType::TT_PSUBC_NC);
    t.Test(TestType::TT_CPSUB);
    t.Test(TestType::TT_CPSUBC);
    t.Test(TestType::TT_CPSUB_NC);
    t.Test(TestType::TT_CPSUBC_NC);

    return 0;
}