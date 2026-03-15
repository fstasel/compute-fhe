#pragma once

namespace computefhe_test
{

    enum TestType
    {
        TT_ENCRYPT_DECRYPT,
        TT_HA,
        TT_FA,
        TT_XOR3,
        TT_MULADD,
        TT_ADD,
        TT_ADDC,
        TT_ADD_NC,
        TT_SUB,
        TT_SUBC,
        TT_SUB_NC,
        TT_NEG,
        TT_CMPNOTEQ,
        TT_CMPEQ,
        TT_CMPLTEQ_U,
        TT_CMPGT_U,
        TT_CMPGTEQ_U,
        TT_CMPLT_U,
        TT_CMPLTEQ,
        TT_CMPGT,
        TT_CMPGTEQ,
        TT_CMPLT,
        TT_FULLMUL,
        TT_MUL
    };

    inline const char *ToString(TestType v)
    {
        switch (v)
        {
        case TT_ENCRYPT_DECRYPT:
            return "ENCRYPT_DECRYPT";
        case TT_HA:
            return "HA";
        case TT_FA:
            return "FA";
        case TT_XOR3:
            return "XOR3";
        case TT_MULADD:
            return "MULADD";
        case TT_ADD:
            return "ADD";
        case TT_ADDC:
            return "ADDC";
        case TT_ADD_NC:
            return "ADD_NC";
        case TT_SUB:
            return "SUB";
        case TT_SUBC:
            return "SUBC";
        case TT_SUB_NC:
            return "SUB_NC";
        case TT_NEG:
            return "NEG";
        case TT_CMPNOTEQ:
            return "CMPNOTEQ";
        case TT_CMPEQ:
            return "CMPEQ";
        case TT_CMPLTEQ_U:
            return "CMPLTEQ_U";
        case TT_CMPGT_U:
            return "CMPGT_U";
        case TT_CMPGTEQ_U:
            return "CMPGTEQ_U";
        case TT_CMPLT_U:
            return "CMPLT_U";
        case TT_CMPLTEQ:
            return "CMPLTEQ";
        case TT_CMPGT:
            return "CMPGT";
        case TT_CMPGTEQ:
            return "CMPGTEQ";
        case TT_CMPLT:
            return "CMPLT";
        case TT_FULLMUL:
            return "FULLMUL";
        case TT_MUL:
            return "MUL";
        default:
            return "[Unknown]";
        }
    }

    enum TestResult
    {
        TR_FAIL,
        TR_SUCCESS
    };
}