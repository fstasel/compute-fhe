#pragma once

namespace computefhe
{

    enum CryptoContextParam
    {
        CCPARAM_STD128,
        CCPARAM_STD128_3,
        CCPARAM_STD128_LMKCDEY,
        CCPARAM_STD128_3_LMKCDEY,
        CCPARAM_STD192,
        CCPARAM_STD192_3,
        CCPARAM_STD192_LMKCDEY,
        CCPARAM_STD192_3_LMKCDEY,
        CCPARAM_STD256,
        CCPARAM_STD256_3,
        CCPARAM_STD256_LMKCDEY,
        CCPARAM_STD256_3_LMKCDEY,
        CCPARAM_TOY
    };

    inline const char *ToString(CryptoContextParam v)
    {
        switch (v)
        {
        case CCPARAM_STD128:
            return "STD128";
        case CCPARAM_STD128_3:
            return "STD128_3";
        case CCPARAM_STD128_LMKCDEY:
            return "STD128_LMKCDEY";
        case CCPARAM_STD128_3_LMKCDEY:
            return "STD128_3_LMKCDEY";
        case CCPARAM_STD192:
            return "STD192";
        case CCPARAM_STD192_3:
            return "STD192_3";
        case CCPARAM_STD192_LMKCDEY:
            return "STD192_LMKCDEY";
        case CCPARAM_STD192_3_LMKCDEY:
            return "STD192_3_LMKCDEY";
        case CCPARAM_STD256:
            return "STD256";
        case CCPARAM_STD256_3:
            return "STD256_3";
        case CCPARAM_STD256_LMKCDEY:
            return "STD256_LMKCDEY";
        case CCPARAM_STD256_3_LMKCDEY:
            return "STD256_3_LMKCDEY";
        case CCPARAM_TOY:
            return "TOY";
        default:
            return "[Unknown]";
        }
    }

    enum ArithmeticsEngineType
    {
        AE_GATELOGIC,
        AE_OPTIMIZED
    };

    inline const char *ToString(ArithmeticsEngineType v)
    {
        switch (v)
        {
        case AE_GATELOGIC:
            return "GATELOGIC";
        case AE_OPTIMIZED:
            return "OPTIMIZED";
        default:
            return "[Unknown]";
        }
    }
}