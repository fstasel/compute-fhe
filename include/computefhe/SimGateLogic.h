#pragma once

#include <computefhe/BaseAESimulator.h>

namespace computefhe {

class SimGateLogic : public BaseAESimulator
{
public:
    SimGateLogic(ComputeFHE *cfhe);

    void HalfAdder();
    void HalfAdder(const LWEPlaintext &b, LWEPlaintext &carry_out_pt, bool &is_carry_ct);
    void HalfSubtractor();
    void HalfSubtractor(const LWEPlaintext &a, LWEPlaintext &carry_out_pt, bool &is_carry_ct);
    void FullAdder();
    void FullAdder(const LWEPlaintext &b, const LWEPlaintext &c, LWEPlaintext &carry_out_pt, bool &is_carry_ct);
    void FullAdder(const LWEPlaintext &c);

    void XOR3();
    void MulAdd(bool carry_out);
    void DigitSum();

    size_t Add_CtCt_FixedPoint(const size_t n_bits, const bool &carry_in, const bool &carry_out);
    size_t Sub_CtCt_FixedPoint(const size_t n_bits, const bool &carry_in, const bool &carry_out);
    size_t Add_CtPt_FixedPoint(const PFixedPoint &b, const bool &carry_in, const bool &carry_out);
    size_t Sub_PtCt_FixedPoint(const PFixedPoint &a, const bool &carry_in, const bool &carry_out);

    size_t Neg_Ct_FixedPoint(const size_t n_bits);

    void CmpNotEq_CtCt_FixedPoint(const size_t n_bits);
    void CmpEq_CtCt_FixedPoint(const size_t n_bits);
    void CmpLTEq_U_CtCt_FixedPoint(const size_t n_bits);
    void CmpGT_U_CtCt_FixedPoint(const size_t n_bits);
    void CmpNotEq_CtPt_FixedPoint(const PFixedPoint &b);
    void CmpEq_CtPt_FixedPoint(const PFixedPoint &b);
    void CmpLTEq_U_CtPt_FixedPoint(const PFixedPoint &b);
    void CmpGT_U_CtPt_FixedPoint(const PFixedPoint &b);

    size_t FullMul_CtCt_FixedPoint(const size_t n_bits);
    size_t FullMul_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b);
    size_t FullMulFast_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b);
    size_t BoothsMul_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b);

    size_t Mul_CtCt_FixedPoint(const size_t n_bits);
    size_t Mul_CtPt_FixedPoint(const PFixedPoint &b);
    size_t MulFast_CtPt_FixedPoint(const PFixedPoint &b);

    void Mux_CCC();
    void Mux_CCP(LWEPlaintext b);
    void Mux_CPP(LWEPlaintext a, LWEPlaintext b, LWEPlaintext &out_pt, bool &is_out_ct);
};
}