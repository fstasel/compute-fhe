#pragma once

#include <computefhe/SimGateLogic.h>

namespace computefhe
{

    class SimOptimized : public SimGateLogic
    {
    public:
        SimOptimized(ComputeFHE *cfhe);

        void FullAdder();

        void XOR3();
        void MulAdd(bool carry_out);
        void DigitSum();

        void CmpLTEq_U_CtCt_FixedPoint(const size_t n_bits);
        void CmpGT_U_CtCt_FixedPoint(const size_t n_bits);

        size_t FullMul_CtCt_FixedPoint(const size_t n_bits);
        size_t Mul_CtCt_FixedPoint(const size_t n_bits);

        size_t Add_CtPt_FixedPoint(const PFixedPoint &b, const bool &carry_in, const bool &carry_out);
        size_t Sub_PtCt_FixedPoint(const PFixedPoint &a, const bool &carry_in, const bool &carry_out);

        size_t Neg_Ct_FixedPoint(const size_t n_bits);

        void Mux_CCC();
    };
}