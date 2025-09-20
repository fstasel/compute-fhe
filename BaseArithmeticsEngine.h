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
    virtual FixedPoint Add(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual FixedPoint AddC(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual FixedPoint AddNC(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual FixedPoint Sub(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual FixedPoint SubC(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual FixedPoint SubNC(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual FixedPoint Neg(const FixedPoint &a) = 0;
    virtual LWECiphertext CmpNotEq(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual LWECiphertext CmpEq(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual LWECiphertext CmpLTEq_U(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual LWECiphertext CmpGT_U(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual LWECiphertext CmpGTEq_U(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual LWECiphertext CmpLT_U(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual LWECiphertext CmpLTEq(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual LWECiphertext CmpGT(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual LWECiphertext CmpGTEq(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual LWECiphertext CmpLT(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual FixedPoint FullMul(const FixedPoint &a, const FixedPoint &b) = 0;
    virtual FixedPoint Mul(const FixedPoint &a, const FixedPoint &b) = 0;

    FixedPoint ToggleMSB(const FixedPoint &a);

    TestReport TestHalfAdder();
    TestReport TestFullAdder();
    TestReport TestXOR3();
    TestReport TestMulAdd();
    TestReport TestAdd(uint n_digits);
    TestReport TestAddC(uint n_digits);
    TestReport TestAddNC(uint n_digits);
    TestReport TestSub(uint n_digits);
    TestReport TestSubC(uint n_digits);
    TestReport TestSubNC(uint n_digits);
    TestReport TestNeg(uint n_digits);
    TestReport TestCmpNotEq(uint n_digits);
    TestReport TestCmpEq(uint n_digits);
    TestReport TestCmpLTEq_U(uint n_digits);
    TestReport TestCmpGT_U(uint n_digits);
    TestReport TestCmpGTEq_U(uint n_digits);
    TestReport TestCmpLT_U(uint n_digits);
    TestReport TestCmpLTEq(uint n_digits);
    TestReport TestCmpGT(uint n_digits);
    TestReport TestCmpGTEq(uint n_digits);
    TestReport TestCmpLT(uint n_digits);
    TestReport TestFullMul(uint n_digits);
    TestReport TestMul(uint n_digits);
};
