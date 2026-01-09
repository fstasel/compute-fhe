#pragma once

#include "AEGateLogic.h"

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

    LWECiphertext CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT_U(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint FullMul(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Mul(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Add_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b,
                                    const bool &carry_in, const bool &carry_out);
    CFixedPoint Sub_PtCt_FixedPoint(const PFixedPoint &a, const CFixedPoint &b,
                                    const bool &carry_in, const bool &carry_out);
    CFixedPoint Neg(const CFixedPoint &a);

    uint Get_CtCtAdd_Cost(size_t n_bits);
    uint Get_CtCtAddNC_Cost(size_t n_bits);
    uint Get_CtCtSubC_Cost(size_t n_bits);
    uint Get_CtPtAddC_Cost(size_t n_bits);
    uint Get_PtCtSub_Cost(size_t n_bits);
    uint Get_CtPtSubCNC_Cost(size_t n_bits);
    uint Get_CtNeg_Cost(size_t n_bits);
};
