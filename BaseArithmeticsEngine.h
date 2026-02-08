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

    virtual LWECiphertext GetCarry();
    virtual LWEPlaintext GetCarryPT();
    virtual void SetCarry(LWEPlaintext value);
    virtual void SetCarry(LWECiphertext value);
    virtual void SetCarry();
    virtual void ResetCarry();
    virtual bool isLastCarryCT();
    virtual void SetIsLastCarryCT(bool val);

    virtual LWECiphertext GetConstantFalse();
    virtual LWECiphertext GetConstantTrue();

    // Abstract
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

    virtual LWECiphertext Mux_CCC(LWECiphertext s, LWECiphertext a, LWECiphertext b) = 0;
    virtual LWECiphertext Mux_CCP(LWECiphertext s, LWECiphertext a, LWEPlaintext b) = 0;
    virtual void Mux_CPP(LWECiphertext s, LWEPlaintext a, LWEPlaintext b,
                         LWECiphertext &out_ct, LWEPlaintext &out_pt, bool &is_out_ct) = 0;

    // Wrappers
    virtual CFixedPoint Add(const CFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint AddC(const CFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint AddNC(const CFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint AddCNC(const CFixedPoint &a, const CFixedPoint &b);

    virtual CFixedPoint Sub(const CFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint SubC(const CFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint SubNC(const CFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint SubCNC(const CFixedPoint &a, const CFixedPoint &b);

    virtual CFixedPoint Add(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint Add(const PFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint AddC(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint AddC(const PFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint AddNC(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint AddNC(const PFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint AddCNC(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint AddCNC(const PFixedPoint &a, const CFixedPoint &b);

    virtual CFixedPoint Sub(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint Sub(const PFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint SubC(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint SubC(const PFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint SubNC(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint SubNC(const PFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint SubCNC(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint SubCNC(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpNotEq(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpNotEq(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpNotEq(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpEq(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpEq(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpEq(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpLTEq_U(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpLTEq_U(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpGT_U(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpGT_U(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpGT_U(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpGTEq_U(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpGTEq_U(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpGTEq_U(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpLT_U(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpLT_U(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpLT_U(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpLTEq(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpLTEq(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpLTEq(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpGT(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpGT(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpGT(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpGTEq(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpGTEq(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpGTEq(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext CmpLT(const CFixedPoint &a, const CFixedPoint &b);
    virtual LWECiphertext CmpLT(const CFixedPoint &a, const PFixedPoint &b);
    virtual LWECiphertext CmpLT(const PFixedPoint &a, const CFixedPoint &b);

    virtual CFixedPoint ToggleMSB(const CFixedPoint &a);
    virtual PFixedPoint ToggleMSB(const PFixedPoint &a);

    virtual LWECiphertext PXOR(ConstLWECiphertext &a, const LWEPlaintext &b);
    virtual LWECiphertext PXOR(const LWEPlaintext &a, ConstLWECiphertext &b);
    virtual LWEPlaintext PXOR(const LWEPlaintext &a, LWEPlaintext &b);

    virtual LWECiphertext PXNOR(ConstLWECiphertext &a, const LWEPlaintext &b);
    virtual LWECiphertext PXNOR(const LWEPlaintext &a, ConstLWECiphertext &b);
    virtual LWEPlaintext PXNOR(const LWEPlaintext &a, LWEPlaintext &b);

    virtual CFixedPoint Neg(const CFixedPoint &a);
    virtual PFixedPoint Neg(const PFixedPoint &a);

    virtual CFixedPoint Not(const CFixedPoint &a);
    virtual PFixedPoint Not(const PFixedPoint &a);

    virtual CFixedPoint FullMul(const CFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint FullMul(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint FullMul(const PFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint FullMulFast(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint FullMulFast(const PFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint BoothsMul(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint BoothsMul(const PFixedPoint &a, const CFixedPoint &b);

    virtual CFixedPoint Mul(const CFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint Mul(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint Mul(const PFixedPoint &a, const CFixedPoint &b);
    virtual CFixedPoint MulFast(const CFixedPoint &a, const PFixedPoint &b);
    virtual CFixedPoint MulFast(const PFixedPoint &a, const CFixedPoint &b);

    virtual LWECiphertext Mux(LWECiphertext s, LWECiphertext a, LWECiphertext b);
    virtual LWECiphertext Mux(LWECiphertext s, LWECiphertext a, LWEPlaintext b);
    virtual LWECiphertext Mux(LWECiphertext s, LWEPlaintext a, LWECiphertext b);
    virtual void Mux(LWECiphertext s, LWEPlaintext a, LWEPlaintext b,
                     LWECiphertext &out_ct, LWEPlaintext &out_pt, bool &is_out_ct);

    virtual CFixedPoint Mux(LWECiphertext s, const CFixedPoint a, const CFixedPoint b);
    virtual CFixedPoint Mux(LWECiphertext s, const CFixedPoint a, const PFixedPoint b);
    virtual CFixedPoint Mux(LWECiphertext s, const PFixedPoint a, const CFixedPoint b);
};
