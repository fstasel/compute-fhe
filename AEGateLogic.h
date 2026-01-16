#pragma once

#include "BaseArithmeticsEngine.h"

class AEGateLogic : public BaseArithmeticsEngine
{
public:
    AEGateLogic(ComputeFHE *cfhe);

    void HalfAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                   LWECiphertext &sum, LWECiphertext &carry_out);
    void HalfAdder(ConstLWECiphertext &a, const LWEPlaintext &b,
                   LWECiphertext &sum, LWECiphertext &carry_out_ct,
                   LWEPlaintext &carry_out_pt, bool &is_carry_ct);

    void HalfSubtractor(ConstLWECiphertext &a, ConstLWECiphertext &b,
                        LWECiphertext &sum, LWECiphertext &carry_out);
    void HalfSubtractor(const LWEPlaintext &a, ConstLWECiphertext &b,
                        LWECiphertext &sum, LWECiphertext &carry_out_ct,
                        LWEPlaintext &carry_out_pt, bool &is_carry_ct);

    void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c,
                   LWECiphertext &sum, LWECiphertext &carry_out);
    void FullAdder(ConstLWECiphertext &a, const LWEPlaintext &b, const LWEPlaintext &c,
                   LWECiphertext &sum, LWECiphertext &carry_out_ct,
                   LWEPlaintext &carry_out_pt, bool &is_carry_ct);
    void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, const LWEPlaintext &c,
                   LWECiphertext &sum, LWECiphertext &carry_out);

    LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c);
    LWECiphertext MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                         LWECiphertext *carry_out = nullptr);
    LWECiphertext DigitSum(ConstLWECiphertext &e1, ConstLWECiphertext &e0, ConstLWECiphertext &s0);

    CFixedPoint Add_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b,
                                    const bool &carry_in, const bool &carry_out);
    CFixedPoint Sub_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b,
                                    const bool &carry_in, const bool &carry_out);
    CFixedPoint Add_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b,
                                    const bool &carry_in, const bool &carry_out);
    CFixedPoint Sub_PtCt_FixedPoint(const PFixedPoint &a, const CFixedPoint &b,
                                    const bool &carry_in, const bool &carry_out);

    CFixedPoint Neg_Ct_FixedPoint(const CFixedPoint &a);

    LWECiphertext CmpNotEq_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpEq_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLTEq_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpNotEq_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
    LWECiphertext CmpEq_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
    LWECiphertext CmpLTEq_U_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
    LWECiphertext CmpGT_U_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);

    CFixedPoint FullMul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint FullMul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint FullMulFast_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint BoothsMul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);

    CFixedPoint Mul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Mul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint MulFast_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);

    virtual uint Get_CtCtAdd_Cost(size_t n_bits);
    virtual uint Get_CtCtAddNC_Cost(size_t n_bits);
    virtual uint Get_CtCtSubC_Cost(size_t n_bits);
    virtual uint Get_CtCtSubNC_Cost(size_t n_bits);
    virtual uint Get_CtPtAddC_Cost(size_t n_bits);
    virtual uint Get_PtCtSub_Cost(size_t n_bits);
    virtual uint Get_CtPtSubCNC_Cost(size_t n_bits);
    virtual uint Get_CtNeg_Cost(size_t n_bits);
    virtual uint Get_PtFullMul_Cost(const PFixedPoint &pt, size_t ct_n_bits, size_t &out_n_bits);
    virtual uint Get_Pt2sCompFullMul_Cost(const PFixedPoint &pt, size_t ct_n_bits);
    virtual uint Get_PtMul_Cost(const PFixedPoint &pt);
    virtual uint Get_Pt2sCompMul_Cost(const PFixedPoint &pt);
    virtual uint Get_BoothsMul_Cost(const PFixedPoint &pt, size_t ct_n_bits);
};
