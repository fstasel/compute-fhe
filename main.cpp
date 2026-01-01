#include "CFHE_Test.h"
// #include "ComputeFHE.h"
// #include "AEGateLogic.h"
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
    t.Test(TT_PFULLMUL, 5);

    // ComputeFHE cfhe(CCPARAM_STD128, AE_GATELOGIC);
    // AEGateLogic *ae = (AEGateLogic *)cfhe.GetArithmeticsEngine();
    // // uint k = 4096+128+8+1;
    // // cout << "FullMul Cost for " << k << " = "
    // //      << ae->Get_PtFullMul_Cost(cfhe.uint2PFixedPoint(k, 16), 4) << endl;
    // for (uint k = 0; k < 16; k++)
    // {
    //     cout << "FullMul Cost for " << k << " = "
    //          << ae->Get_PtFullMul_Cost(cfhe.uint2PFixedPoint(k, 4), 4) << " " << ae->Get_Pt2sCompFullMul_Cost(cfhe.uint2PFixedPoint(k, 4), 4) << endl;
    // }

    return EXIT_SUCCESS;
}
