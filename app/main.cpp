#include "CFHE_Test.h"

using namespace computefhe;
using namespace computefhe_test;

int main()
{
    CFHE_Test::TestAll();
    CFHE_Test::TestAllNoise();

    return EXIT_SUCCESS;
}
