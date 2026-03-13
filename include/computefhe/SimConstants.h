#pragma once

#include <computefhe/CFHETypes.h>
#include <vector>

using namespace std;

// Tested by using OpenFHE 1.4.2
// Param    Var.Fresh	Var.BS	Avg.BSTime	StdevBSTime	ModQ	Stdev BS	        Norm Stdev BS
// STD128	10.0406	    256.391	72	        0.6	        1024	16.0122140880017	0.0156369278203142
// STD128_3	10.1711	    49.4529	112	        1.0	        1024	7.03227559186925	0.00686745663268481
// STD192	10.2903	    1193.7	155     	0.5	        2048	34.549963820531	    0.0168700995217436
// STD192_3	10.181	    1080.25	172     	0.6	        4096	32.8671568590896	0.00802420821755117
// STD256	10.1229	    579.518	304	        1.0	        2048	24.0731800973615	0.0117544824694148
// STD256_3	10.0277	    157.386	427	        1.5	        2048	12.5453577071361	0.00612566294293757

namespace computefhe {

class SimConstants
{
public:
    static void initSimConstants(vector<uint> &bs_time, vector<double> &bs_stdev)
    {
        bs_time.resize(13);
        bs_stdev.resize(13);
        //
        bs_time[CCPARAM_STD128] = 72;
        bs_time[CCPARAM_STD128_3] = 112;
        bs_time[CCPARAM_STD192] = 155;
        bs_time[CCPARAM_STD192_3] = 172;
        bs_time[CCPARAM_STD256] = 304;
        bs_time[CCPARAM_STD256_3] = 427;
        //
        bs_stdev[CCPARAM_STD128] = 0.0156369278203142;
        bs_stdev[CCPARAM_STD128_3] = 0.00686745663268481;
        bs_stdev[CCPARAM_STD192] = 0.0168700995217436;
        bs_stdev[CCPARAM_STD192_3] = 0.00802420821755117;
        bs_stdev[CCPARAM_STD256] = 0.0117544824694148;
        bs_stdev[CCPARAM_STD256_3] = 0.00612566294293757;
    }
};
}