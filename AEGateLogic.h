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

    CFixedPoint Neg(const CFixedPoint &a);
    LWECiphertext CmpNotEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLT_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLTEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGTEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLT(const CFixedPoint &a, const CFixedPoint &b);

    CFixedPoint FullMul(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint FullMul(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint FullMulFast(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint BoothsMul(const CFixedPoint &a, const PFixedPoint &b);

    CFixedPoint Mul(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Mul(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint MulFast(const CFixedPoint &a, const PFixedPoint &b);

    virtual uint Get_CtCtAdd_Cost(size_t n_bits);
    virtual uint Get_CtCtAddNC_Cost(size_t n_bits);
    virtual uint Get_CtCtSubC_Cost(size_t n_bits);
    virtual uint Get_CtPtAddC_Cost(size_t n_bits);
    virtual uint Get_PtCtSub_Cost(size_t n_bits);
    virtual uint Get_CtPtSubCNC_Cost(size_t n_bits);
    virtual uint Get_CtNeg_Cost(size_t n_bits);
    virtual uint Get_PtFullMul_Cost(const PFixedPoint &pt, size_t ct_n_bits, size_t &out_n_bits);
    virtual uint Get_Pt2sCompFullMul_Cost(const PFixedPoint &pt, size_t ct_n_bits);
    virtual uint Get_PtMul_Cost(const PFixedPoint &pt);
    virtual uint Get_Pt2sCompMul_Cost(const PFixedPoint &pt);
};
