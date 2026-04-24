#include "include/CFHE_Test.h"

using namespace computefhe_test;

int main() {
    // CFHE_Test::TestAll();
    // CFHE_Test::TestAllNoise();

    CFHE_Test t(CCPARAM_TOY, ALU_STANDARD, false);
    t.SetRegenerateKeys(false);
    t.SetNumTest(100);
    t.SetVerbosity(0);
    t.Test(TT_PCMPEQ, 4);
    t.Test(TT_PCMPNOTEQ, 4);
    t.Test(TT_PCMPGT_U, 4);
    t.Test(TT_PCMPGTEQ_U, 4);
    t.Test(TT_PCMPLT_U, 4);
    t.Test(TT_PCMPLTEQ_U, 4);
    t.Test(TT_PCMPGT, 4);
    t.Test(TT_PCMPGTEQ, 4);
    t.Test(TT_PCMPLT, 4);
    t.Test(TT_PCMPLTEQ, 4);

    return 0;
}