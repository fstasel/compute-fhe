#pragma once

#include <computefhe/AEGateLogic.h>

namespace computefhe {

class AEOptimized : public AEGateLogic
{
public:
    AEOptimized(ComputeFHE *cfhe);

    void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c,
                   LWECiphertext &sum, LWECiphertext &carry_out);
    LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c);
    LWECiphertext MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                         LWECiphertext *carry_out = nullptr);
    LWECiphertext DigitSum(ConstLWECiphertext &e1, ConstLWECiphertext &e0, ConstLWECiphertext &s0);

    LWECiphertext CmpLTEq_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);

    CFixedPoint FullMul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Mul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);

    CFixedPoint Add_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b,
                                    const bool &carry_in, const bool &carry_out);
    CFixedPoint Sub_PtCt_FixedPoint(const PFixedPoint &a, const CFixedPoint &b,
                                    const bool &carry_in, const bool &carry_out);
    CFixedPoint Neg_Ct_FixedPoint(const CFixedPoint &a);

    LWECiphertext Mux_CCC(LWECiphertext s, LWECiphertext a, LWECiphertext b);

    uint Get_CtCtAdd_Cost(size_t n_bits);
    uint Get_CtCtAddNC_Cost(size_t n_bits);
    uint Get_CtCtSubC_Cost(size_t n_bits);
    uint Get_CtPtAddC_Cost(size_t n_bits);
    uint Get_PtCtSub_Cost(size_t n_bits);
    uint Get_CtPtSubCNC_Cost(size_t n_bits);
    uint Get_CtNeg_Cost(size_t n_bits);
};
}