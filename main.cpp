#include "CFHE_Test.h"

#include <iostream>
using namespace std;

int main()
{
    // CFHE_Test::TestAll();
    // CFHE_Test::TestAllNoise();

    CFHE_Test t(CCPARAM_STD128, AE_GATELOGIC);
    t.SetNumTest(100);
    t.SetVerbosity(4);
    t.SetRegenerateKeys(false);
    t.Test(TT_PSUB_NC, 4);

    return EXIT_SUCCESS;
}
