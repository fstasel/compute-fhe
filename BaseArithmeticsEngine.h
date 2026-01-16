#pragma once

#include "ComputeFHE.h"

using namespace lbcrypto;

class ComputeFHE;

class BaseArithmeticsEngine
{
protected:
    LWECiphertext carry;
    LWEPlaintext carry_pt = 0;
    bool is_lastcarry_ct = false;

    ComputeFHE *cfhe_base;

public:
    BaseArithmeticsEngine(ComputeFHE *cfhe);
    virtual ~BaseArithmeticsEngine();

    LWECiphertext GetCarry();
    LWEPlaintext GetCarryPT();
    void SetCarry(LWEPlaintext value);
    void SetCarry(LWECiphertext value);
    void SetCarry();
    void ResetCarry();
    bool isLastCarryCT();
    void SetIsLastCarryCT(bool val);

    LWECiphertext GetConstantFalse();
    LWECiphertext GetConstantTrue();

    virtual void HalfAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                           LWECiphertext &sum, LWECiphertext &carry_out) = 0;
    virtual void HalfAdder(ConstLWECiphertext &a, const LWEPlaintext &b,
                           LWECiphertext &sum, LWECiphertext &carry_out_ct,
                           LWEPlaintext &carry_out_pt, bool &is_carry_ct) = 0;

    virtual void HalfSubtractor(ConstLWECiphertext &a, ConstLWECiphertext &b,
                                LWECiphertext &sum, LWECiphertext &carry_out) = 0;
    virtual void HalfSubtractor(const LWEPlaintext &a, ConstLWECiphertext &b,
                                LWECiphertext &sum, LWECiphertext &carry_out_ct,
                                LWEPlaintext &carry_out_pt, bool &is_carry_ct) = 0;

    virtual void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c,
                           LWECiphertext &sum, LWECiphertext &carry_out) = 0;
    virtual void FullAdder(ConstLWECiphertext &a, const LWEPlaintext &b, const LWEPlaintext &c,
                           LWECiphertext &sum, LWECiphertext &carry_out_ct,
                           LWEPlaintext &carry_out_pt, bool &is_carry_ct) = 0;
    virtual void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, const LWEPlaintext &c,
                           LWECiphertext &sum, LWECiphertext &carry_out) = 0;

    virtual LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c) = 0;
    virtual LWECiphertext MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                                 LWECiphertext *carry_out = nullptr) = 0;
    virtual LWECiphertext DigitSum(ConstLWECiphertext &e1, ConstLWECiphertext &e0, ConstLWECiphertext &s0) = 0;

    virtual CFixedPoint Add_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b,
                                            const bool &carry_in, const bool &carry_out) = 0;
    virtual CFixedPoint Sub_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b,
                                            const bool &carry_in, const bool &carry_out) = 0;
    virtual CFixedPoint Add_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b,
                                            const bool &carry_in, const bool &carry_out) = 0;
    virtual CFixedPoint Sub_PtCt_FixedPoint(const PFixedPoint &a, const CFixedPoint &b,
                                            const bool &carry_in, const bool &carry_out) = 0;

    virtual CFixedPoint Neg_Ct_FixedPoint(const CFixedPoint &a) = 0;

    virtual LWECiphertext CmpNotEq_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpEq_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpLTEq_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpGT_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpNotEq_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b) = 0;
    virtual LWECiphertext CmpEq_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b) = 0;
    virtual LWECiphertext CmpLTEq_U_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b) = 0;
    virtual LWECiphertext CmpGT_U_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b) = 0;

    virtual CFixedPoint FullMul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint FullMul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b) = 0;
    virtual CFixedPoint FullMulFast_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b) = 0;
    virtual CFixedPoint BoothsMul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b) = 0;

    virtual CFixedPoint Mul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint Mul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b) = 0;
    virtual CFixedPoint MulFast_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b) = 0;

    CFixedPoint Add(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint AddC(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint AddNC(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint AddCNC(const CFixedPoint &a, const CFixedPoint &b);

    CFixedPoint Sub(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubC(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubNC(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubCNC(const CFixedPoint &a, const CFixedPoint &b);

    CFixedPoint Add(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint Add(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint AddC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint AddC(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint AddNC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint AddNC(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint AddCNC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint AddCNC(const PFixedPoint &a, const CFixedPoint &b);

    CFixedPoint Sub(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint Sub(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint SubC(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubNC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint SubNC(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint SubCNC(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint SubCNC(const PFixedPoint &a, const CFixedPoint &b);

    LWECiphertext CmpNotEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpNotEq(const CFixedPoint &a, const PFixedPoint &b);
    LWECiphertext CmpNotEq(const PFixedPoint &a, const CFixedPoint &b);

    LWECiphertext CmpEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpEq(const CFixedPoint &a, const PFixedPoint &b);
    LWECiphertext CmpEq(const PFixedPoint &a, const CFixedPoint &b);

    LWECiphertext CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLTEq_U(const CFixedPoint &a, const PFixedPoint &b);
    LWECiphertext CmpLTEq_U(const PFixedPoint &a, const CFixedPoint &b);

    LWECiphertext CmpGT_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT_U(const CFixedPoint &a, const PFixedPoint &b);
    LWECiphertext CmpGT_U(const PFixedPoint &a, const CFixedPoint &b);

    LWECiphertext CmpGTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGTEq_U(const CFixedPoint &a, const PFixedPoint &b);
    LWECiphertext CmpGTEq_U(const PFixedPoint &a, const CFixedPoint &b);

    LWECiphertext CmpLT_U(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLT_U(const CFixedPoint &a, const PFixedPoint &b);
    LWECiphertext CmpLT_U(const PFixedPoint &a, const CFixedPoint &b);

    LWECiphertext CmpLTEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGT(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpGTEq(const CFixedPoint &a, const CFixedPoint &b);
    LWECiphertext CmpLT(const CFixedPoint &a, const CFixedPoint &b);

    CFixedPoint ToggleMSB(const CFixedPoint &a);

    LWECiphertext PXOR(ConstLWECiphertext &a, const LWEPlaintext &b);
    LWECiphertext PXOR(const LWEPlaintext &a, ConstLWECiphertext &b);

    LWECiphertext PXNOR(ConstLWECiphertext &a, const LWEPlaintext &b);
    LWECiphertext PXNOR(const LWEPlaintext &a, ConstLWECiphertext &b);

    CFixedPoint Neg(const CFixedPoint &a);
    PFixedPoint Neg(const PFixedPoint &a);

    CFixedPoint Not(const CFixedPoint &a);
    PFixedPoint Not(const PFixedPoint &a);

    CFixedPoint FullMul(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint FullMul(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint FullMul(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint FullMulFast(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint FullMulFast(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint BoothsMul(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint BoothsMul(const PFixedPoint &a, const CFixedPoint &b);

    CFixedPoint Mul(const CFixedPoint &a, const CFixedPoint &b);
    CFixedPoint Mul(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint Mul(const PFixedPoint &a, const CFixedPoint &b);
    CFixedPoint MulFast(const CFixedPoint &a, const PFixedPoint &b);
    CFixedPoint MulFast(const PFixedPoint &a, const CFixedPoint &b);
};
