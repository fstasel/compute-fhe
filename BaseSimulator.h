#pragma once

#include "ComputeFHE.h"

using namespace lbcrypto;

class ComputeFHE;

class BaseSimulator
{
protected:
    LWEPlaintext carry_pt = 0;
    bool is_lastcarry_ct = false;

    uint num_bs = 0;
    uint num_not = 0;
    uint num_andor = 0;
    uint num_xorxnor = 0;
    uint num_xor3 = 0;
    uint num_maj = 0;
    uint num_ma = 0;
    uint num_mac = 0;
    uint num_ds = 0;

    ComputeFHE *cfhe_base;

public:
    BaseSimulator(ComputeFHE *cfhe);
    virtual ~BaseSimulator();

    LWEPlaintext GetCarryPT();
    void SetCarry(LWEPlaintext value);
    void SetCarry();
    void ResetCarry();
    bool isLastCarryCT();
    void SetIsLastCarryCT(bool val);

    void PrintStats();
    void ResetStats();

    virtual void HalfAdder() = 0;
    virtual void HalfAdder(const LWEPlaintext &b, LWEPlaintext &carry_out_pt, bool &is_carry_ct) = 0;
    virtual void HalfSubtractor() = 0;
    virtual void HalfSubtractor(const LWEPlaintext &a, LWEPlaintext &carry_out_pt, bool &is_carry_ct) = 0;
    virtual void FullAdder() = 0;
    virtual void FullAdder(const LWEPlaintext &b, const LWEPlaintext &c, LWEPlaintext &carry_out_pt, bool &is_carry_ct) = 0;
    virtual void FullAdder(const LWEPlaintext &c) = 0;

    virtual void XOR3() = 0;
    virtual void MulAdd(bool carry_out) = 0;
    virtual void DigitSum() = 0;

    virtual size_t Add_CtCt_FixedPoint(const size_t n_bits, const bool &carry_in, const bool &carry_out) = 0;
    virtual size_t Sub_CtCt_FixedPoint(const size_t n_bits, const bool &carry_in, const bool &carry_out) = 0;
    virtual size_t Add_CtPt_FixedPoint(const PFixedPoint &b, const bool &carry_in, const bool &carry_out) = 0;
    virtual size_t Sub_PtCt_FixedPoint(const PFixedPoint &a, const bool &carry_in, const bool &carry_out) = 0;

    virtual size_t Neg_Ct_FixedPoint(const size_t n_bits) = 0;

    virtual void CmpNotEq_CtCt_FixedPoint(const size_t n_bits) = 0;
    virtual void CmpEq_CtCt_FixedPoint(const size_t n_bits) = 0;
    virtual void CmpLTEq_U_CtCt_FixedPoint(const size_t n_bits) = 0;
    virtual void CmpGT_U_CtCt_FixedPoint(const size_t n_bits) = 0;
    virtual void CmpNotEq_CtPt_FixedPoint(const PFixedPoint &b) = 0;
    virtual void CmpEq_CtPt_FixedPoint(const PFixedPoint &b) = 0;
    virtual void CmpLTEq_U_CtPt_FixedPoint(const PFixedPoint &b) = 0;
    virtual void CmpGT_U_CtPt_FixedPoint(const PFixedPoint &b) = 0;

    virtual size_t FullMul_CtCt_FixedPoint(const size_t n_bits) = 0;
    virtual size_t FullMul_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b) = 0;
    virtual size_t FullMulFast_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b) = 0;
    virtual size_t BoothsMul_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b) = 0;

    virtual size_t Mul_CtCt_FixedPoint(const size_t n_bits) = 0;
    virtual size_t Mul_CtPt_FixedPoint(const PFixedPoint &b) = 0;
    virtual size_t MulFast_CtPt_FixedPoint(const PFixedPoint &b) = 0;

    virtual void Mux_CCC() = 0;
    virtual void Mux_CCP(LWEPlaintext b) = 0;
    virtual void Mux_CPP(LWEPlaintext a, LWEPlaintext b, LWEPlaintext &out_pt, bool &is_out_ct) = 0;

    size_t Add(const size_t n_bits);
    size_t AddC(const size_t n_bits);
    size_t AddNC(const size_t n_bits);
    size_t AddCNC(const size_t n_bits);

    size_t Sub(const size_t n_bits);
    size_t SubC(const size_t n_bits);
    size_t SubNC(const size_t n_bits);
    size_t SubCNC(const size_t n_bits);

    size_t Add(const PFixedPoint &b);
    size_t AddC(const PFixedPoint &b);
    size_t AddNC(const PFixedPoint &b);
    size_t AddCNC(const PFixedPoint &b);

    size_t Sub(const int a, const PFixedPoint &b);
    size_t Sub(const PFixedPoint &a);
    size_t SubC(const int a, const PFixedPoint &b);
    size_t SubC(const PFixedPoint &a);
    size_t SubNC(const int a, const PFixedPoint &b);
    size_t SubNC(const PFixedPoint &a);
    size_t SubCNC(const int a, const PFixedPoint &b);
    size_t SubCNC(const PFixedPoint &a);

    void CmpNotEq(const size_t n_bits);
    void CmpNotEq(const PFixedPoint &b);

    void CmpEq(const size_t n_bits);
    void CmpEq(const PFixedPoint &b);

    void CmpLTEq_U(const size_t n_bits);
    void CmpLTEq_U(const int a, const PFixedPoint &b);
    void CmpLTEq_U(const PFixedPoint &a);

    void CmpGT_U(const size_t n_bits);
    void CmpGT_U(const int a, const PFixedPoint &b);
    void CmpGT_U(const PFixedPoint &a);

    void CmpGTEq_U(const size_t n_bits);
    void CmpGTEq_U(const int a, const PFixedPoint &b);
    void CmpGTEq_U(const PFixedPoint &a);

    void CmpLT_U(const size_t n_bits);
    void CmpLT_U(const int a, const PFixedPoint &b);
    void CmpLT_U(const PFixedPoint &a);

    void CmpLTEq(const size_t n_bits);
    void CmpLTEq(const int a, const PFixedPoint &b);
    void CmpLTEq(const PFixedPoint &a);

    void CmpGT(const size_t n_bits);
    void CmpGT(const int a, const PFixedPoint &b);
    void CmpGT(const PFixedPoint &a);

    void CmpGTEq(const size_t n_bits);
    void CmpGTEq(const int a, const PFixedPoint &b);
    void CmpGTEq(const PFixedPoint &a);

    void CmpLT(const size_t n_bits);
    void CmpLT(const int a, const PFixedPoint &b);
    void CmpLT(const PFixedPoint &a);

    size_t ToggleMSB(const size_t n_bits);
    PFixedPoint ToggleMSB(const PFixedPoint &a);

    void PXOR(const LWEPlaintext &b);
    void PXNOR(const LWEPlaintext &b);

    size_t Neg(const size_t n_bits);
    PFixedPoint Neg(const PFixedPoint &a);

    size_t Not(const size_t n_bits);
    PFixedPoint Not(const PFixedPoint &a);

    size_t FullMul(const size_t n_bits);
    size_t FullMul(const size_t n_bits, const PFixedPoint &b);
    size_t FullMulFast(const size_t n_bits, const PFixedPoint &b);
    size_t BoothsMul(const size_t n_bits, const PFixedPoint &b);

    size_t Mul(const size_t n_bits);
    size_t Mul(const PFixedPoint &b);
    size_t MulFast(const PFixedPoint &b);

    void Mux();
    void Mux(LWEPlaintext b);
    void Mux(int s, LWEPlaintext a);
    void Mux(LWEPlaintext a, LWEPlaintext b, LWEPlaintext &out_pt, bool &is_out_ct);

    size_t Mux(const size_t n_bits);
    size_t Mux(const PFixedPoint b);
    size_t Mux(int s, const PFixedPoint a);
};
