#pragma once

#include "ComputeFHE.h"

using namespace lbcrypto;

class ComputeFHE;

class BaseArithmeticsEngine
{
protected:
    LWECiphertext carry;
    ComputeFHE *cfhe_base;

public:
    BaseArithmeticsEngine(ComputeFHE *cfhe);
    virtual ~BaseArithmeticsEngine();

    LWECiphertext GetCarry();
    void SetCarry(LWECiphertext value);
    void SetCarry();
    void ResetCarry();
    LWECiphertext GetConstantFalse();
    LWECiphertext GetConstantTrue();

    virtual void HalfAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                           LWECiphertext &sum, LWECiphertext &carry_out) = 0;
    virtual void HalfSubtractor(ConstLWECiphertext &a, ConstLWECiphertext &b,
                                LWECiphertext &sum, LWECiphertext &carry_out) = 0;
    virtual void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c,
                           LWECiphertext &sum, LWECiphertext &carry_out) = 0;
    virtual LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c) = 0;
    virtual LWECiphertext MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                                 LWECiphertext *carry_out = nullptr) = 0;
    virtual CFixedPoint Add(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint AddC(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint AddNC(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint Sub(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint SubC(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint SubNC(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint Neg(const CFixedPoint &a) = 0;
    virtual LWECiphertext CmpNotEq(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpEq(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpLTEq_U(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpGT_U(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpGTEq_U(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpLT_U(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpLTEq(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpGT(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpGTEq(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual LWECiphertext CmpLT(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint FullMul(const CFixedPoint &a, const CFixedPoint &b) = 0;
    virtual CFixedPoint Mul(const CFixedPoint &a, const CFixedPoint &b) = 0;

    CFixedPoint ToggleMSB(const CFixedPoint &a);
};
