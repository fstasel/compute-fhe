#include <computefhe/ALUStandard.h>
#include <computefhe/ComputeFHE.h>

using namespace computefhe;

ALUOptimized::ALUOptimized(ComputeFHE *cfhe)
    : BaseALU(cfhe), ALUStandard(cfhe) {}

BinaryDigit ALUOptimized::FHE_MAJ(const BinaryDigit &a, const BinaryDigit &b,
                                  const BinaryDigit &c) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(MAJORITY, {a.c, b.c, c.c});
}

BinaryDigit ALUOptimized::FHE_XOR3(const BinaryDigit &a, const BinaryDigit &b,
                                   const BinaryDigit &c) {
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    BinaryDigit sum = a;
    lwe->EvalAddEq(sum, b);
    sum = cc.EvalBinGate(XOR, sum, c);
    return sum;
}

BinaryDigit ALUOptimized::FHE_MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                                     const BinaryDigit &b,
                                     BinaryDigit *carry_out) {
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    BinaryDigit a_2b = b;
    lwe->EvalAddEq(a_2b, a_2b);
    lwe->EvalAddEq(a_2b, a);
    BinaryDigit ma_2b = cc.EvalBinGate(AND, m, a_2b);
    if (carry_out) {
        BinaryDigit neg_b = b;
        lwe->EvalMultConstEq(neg_b, -1);
        *carry_out = cc.EvalBinGate(AND, ma_2b, neg_b);
    }
    return ma_2b;
}

BinaryDigit ALUOptimized::FHE_MUX(const BinaryDigit &s, const BinaryDigit &a,
                                  const BinaryDigit &b) {
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    BinaryDigit t = cc.EvalBinGate(OR, s, a);
    lwe->EvalAddEq(t, t);
    lwe->EvalSubEq(t, b);
    return cc.EvalBinGate(OR, s, t);
}

BinaryDigit ALUOptimized::FHE_DigitSum(const BinaryDigit &e1,
                                       const BinaryDigit &e0,
                                       const BinaryDigit &s0) {
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    BinaryDigit s0_2e1_e0 = e1;
    lwe->EvalAddEq(s0_2e1_e0, s0_2e1_e0);
    lwe->EvalSubEq(s0_2e1_e0, e0);
    s0_2e1_e0 = cc.EvalBinGate(AND, s0_2e1_e0, s0);
    return s0_2e1_e0;
}

BinaryDigit ALUOptimized::Gate_MAJ(const BinaryDigit &a, const BinaryDigit &b,
                                   const BinaryDigit &c) {
    if (a.is_ct && b.is_ct && c.is_ct) {
        return FHE_MAJ(a, b, c);
    }
    if (!a.is_ct && !b.is_ct && !c.is_ct) {
        return (a.p + b.p + c.p >= 2) ? Constant1() : Constant0();
    }
    if (a.is_ct && b.is_ct) {
        return c.p ? Gate_OR(a, b) : Gate_AND(a, b);
    }
    if (a.is_ct && c.is_ct) {
        return b.p ? Gate_OR(a, c) : Gate_AND(a, c);
    }
    if (b.is_ct && c.is_ct) {
        return a.p ? Gate_OR(b, c) : Gate_AND(b, c);
    }
    if (a.is_ct) {
        return (b.p == c.p) ? b : a;
    }
    if (b.is_ct) {
        return (a.p == c.p) ? a : b;
    }
    if (c.is_ct) {
        return (a.p == b.p) ? a : c;
    }
    return Constant0();
}

BinaryDigit ALUOptimized::Gate_XOR3(const BinaryDigit &a, const BinaryDigit &b,
                                    const BinaryDigit &c) {
    if (a.is_ct && b.is_ct && c.is_ct) {
        return FHE_XOR3(a, b, c);
    }
    return Gate_XOR(Gate_XOR(a, b), c);
}

BinaryDigit ALUOptimized::Gate_MulAdd(const BinaryDigit &m,
                                      const BinaryDigit &a,
                                      const BinaryDigit &b,
                                      BinaryDigit *carry_out) {
    if (m.is_ct && a.is_ct && b.is_ct) {
        return FHE_MulAdd(m, a, b, carry_out);
    }
    BinaryDigit ma = Gate_AND(m, a);
    if (carry_out) {
        *carry_out = Gate_AND(ma, b);
    }
    return Gate_XOR(ma, b);
}

BinaryDigit ALUOptimized::Gate_DigitSum(const BinaryDigit &e1,
                                        const BinaryDigit &e0,
                                        const BinaryDigit &s0) {
    if (e0.is_ct && e1.is_ct && s0.is_ct) {
        return FHE_DigitSum(e1, e0, s0);
    }
    BinaryDigit t = Gate_AND(e0, Gate_NOT(s0));
    BinaryDigit s1 = Gate_XOR(e1, t);
    return s1;
}

void ALUOptimized::FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                             const BinaryDigit &c, BinaryDigit &sum,
                             BinaryDigit &carry_out) {
    BinaryDigit s = Gate_XOR3(a, b, c);
    carry_out = Gate_MAJ(a, b, c);
    sum = s;
}

BinaryDigit ALUOptimized::CmpLTEq_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    BinaryDigit inv_a = Gate_NOT(a[0]);
    BinaryDigit c = Gate_OR(inv_a, b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_a = Gate_NOT(a[i]);
        c = Gate_MAJ(inv_a, b[i], c);
    }
    return c;
}

BinaryDigit ALUOptimized::CmpGT_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    BinaryDigit inv_b = Gate_NOT(b[0]);
    BinaryDigit c = Gate_AND(a[0], inv_b);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_b = Gate_NOT(b[i]);
        c = Gate_MAJ(a[i], inv_b, c);
    }
    return c;
}

FixedPoint ALUOptimized::FullMul(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out((n_digit == 1) ? 1 : (n_digit << 1));
    for (uint8_t i = 0; i < n_digit; i++) {
        out[i] = Gate_AND(a[i], b[0]);
    }
    for (uint8_t j = 1; j < n_digit; j++) {
        for (uint8_t i = 0; i < n_digit; i++) {
            if (i == 0) {
                out[i + j] = Gate_MulAdd(a[i], b[j], out[i + j], &carry);
            } else if (i < n_digit - 1) {
                BinaryDigit p = Gate_AND(a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j == 1) {
                out[i + j] = Gate_MulAdd(a[i], b[j], carry,
                                         &(BinaryDigit &)out[i + j + 1]);
            } else {
                BinaryDigit p = Gate_AND(a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], out[i + j + 1]);
            }
        }
    }
    return out;
}

FixedPoint ALUOptimized::Mul(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        out[i] = Gate_AND(a[i], b[0]);
    }
    for (uint8_t j = 1; j < n_digit; j++) {
        for (uint8_t i = 0; i < n_digit - j; i++) {
            if (i == 0 && j < n_digit - 1) {
                out[i + j] = Gate_MulAdd(a[i], b[j], out[i + j], &carry);
            } else if (i < n_digit - j - 1) {
                BinaryDigit p = Gate_AND(a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j < n_digit - 1) {
                BinaryDigit p = Gate_AND(a[i], b[j]);
                out[i + j] = Gate_XOR3(out[i + j], carry, p);
            } else {
                out[i + j] = Gate_MulAdd(a[i], b[j], out[i + j]);
            }
        }
    }
    return out;
}

void ALUOptimized::Swap_if(const BinaryDigit &cond, BinaryDigit &a,
                           BinaryDigit &b) {
    BinaryDigit t = a;
    a = Gate_MUX(cond, t, b);
    b = Gate_XOR3(a, b, t);
}

FixedPoint ALUOptimized::PAdd(const FixedPoint &a, const FixedPoint &pb) {
    if (a.size() != pb.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    ALUStandard::HalfAdder(a[0], pb[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        if (carry.is_ct) {
            out[i] = Gate_XOR(Gate_DigitSum(Gate_XOR(a[i], pb[i - 1]),
                                            Gate_XOR(a[i - 1], pb[i - 1]),
                                            Gate_XOR(out[i - 1], pb[i - 1])),
                              pb[i]);
            if (i == n_digit - 1) {
                carry = (pb[i].p == 0) ? Gate_AND(a[i], Gate_NOT(out[i]))
                                       : Gate_OR(a[i], Gate_NOT(out[i]));
            }
        } else {
            ALUStandard::FullAdder(a[i], pb[i], carry, out[i], carry);
        }
    }
    return out;
}

FixedPoint ALUOptimized::PAddC(const FixedPoint &a, const FixedPoint &pb) {
    if (a.size() != pb.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        if (i > 0 && carry.is_ct) {
            out[i] = Gate_XOR(Gate_DigitSum(Gate_XOR(a[i], pb[i - 1]),
                                            Gate_XOR(a[i - 1], pb[i - 1]),
                                            Gate_XOR(out[i - 1], pb[i - 1])),
                              pb[i]);
            if (i == n_digit - 1) {
                carry = (pb[i].p == 0) ? Gate_AND(a[i], Gate_NOT(out[i]))
                                       : Gate_OR(a[i], Gate_NOT(out[i]));
            }
        } else {
            ALUStandard::FullAdder(a[i], pb[i], carry, out[i], carry);
        }
    }
    return out;
}

FixedPoint ALUOptimized::PAddNC(const FixedPoint &a, const FixedPoint &pb) {
    if (a.size() != pb.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    ALUStandard::HalfAdder(a[0], pb[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        if (carry.is_ct) {
            out[i] = Gate_XOR(Gate_DigitSum(Gate_XOR(a[i], pb[i - 1]),
                                            Gate_XOR(a[i - 1], pb[i - 1]),
                                            Gate_XOR(out[i - 1], pb[i - 1])),
                              pb[i]);
        } else {
            ALUStandard::FullAdder(a[i], pb[i], carry, out[i], carry);
        }
    }
    return out;
}

FixedPoint ALUOptimized::PAddCNC(const FixedPoint &a, const FixedPoint &pb) {
    if (a.size() != pb.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        if (i > 0 && carry.is_ct) {
            out[i] = Gate_XOR(Gate_DigitSum(Gate_XOR(a[i], pb[i - 1]),
                                            Gate_XOR(a[i - 1], pb[i - 1]),
                                            Gate_XOR(out[i - 1], pb[i - 1])),
                              pb[i]);
        } else {
            ALUStandard::FullAdder(a[i], pb[i], carry, out[i], carry);
        }
    }
    return out;
}

FixedPoint ALUOptimized::PSub(const FixedPoint &pa, const FixedPoint &b) {
    if (pa.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = b.size();

    FixedPoint out(n_digit);
    ALUStandard::HalfSubtractor(pa[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        if (carry.is_ct) {
            out[i] = Gate_XOR(Gate_DigitSum(Gate_XNOR(b[i], pa[i - 1]),
                                            Gate_XNOR(b[i - 1], pa[i - 1]),
                                            Gate_XOR(out[i - 1], pa[i - 1])),
                              pa[i]);
            if (i == n_digit - 1) {
                carry = (pa[i].p == 0) ? Gate_NOR(b[i], out[i])
                                       : Gate_NAND(b[i], out[i]);
            }
        } else {
            ALUStandard::FullAdder(Gate_NOT(b[i]), pa[i], carry, out[i], carry);
        }
    }
    return out;
}

FixedPoint ALUOptimized::PSubC(const FixedPoint &pa, const FixedPoint &b) {
    if (pa.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = b.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        if (i > 0 && carry.is_ct) {
            out[i] = Gate_XOR(Gate_DigitSum(Gate_XNOR(b[i], pa[i - 1]),
                                            Gate_XNOR(b[i - 1], pa[i - 1]),
                                            Gate_XOR(out[i - 1], pa[i - 1])),
                              pa[i]);
            if (i == n_digit - 1) {
                carry = (pa[i].p == 0) ? Gate_NOR(b[i], out[i])
                                       : Gate_NAND(b[i], out[i]);
            }
        } else {
            ALUStandard::FullAdder(Gate_NOT(b[i]), pa[i], carry, out[i], carry);
        }
    }
    return out;
}

FixedPoint ALUOptimized::PSubNC(const FixedPoint &pa, const FixedPoint &b) {
    if (pa.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = b.size();

    FixedPoint out(n_digit);
    ALUStandard::HalfSubtractor(pa[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        if (carry.is_ct) {
            out[i] = Gate_XOR(Gate_DigitSum(Gate_XNOR(b[i], pa[i - 1]),
                                            Gate_XNOR(b[i - 1], pa[i - 1]),
                                            Gate_XOR(out[i - 1], pa[i - 1])),
                              pa[i]);
        } else {
            ALUStandard::FullAdder(Gate_NOT(b[i]), pa[i], carry, out[i], carry);
        }
    }
    return out;
}

FixedPoint ALUOptimized::PSubCNC(const FixedPoint &pa, const FixedPoint &b) {
    if (pa.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = b.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        if (i > 0 && carry.is_ct) {
            out[i] = Gate_XOR(Gate_DigitSum(Gate_XNOR(b[i], pa[i - 1]),
                                            Gate_XNOR(b[i - 1], pa[i - 1]),
                                            Gate_XOR(out[i - 1], pa[i - 1])),
                              pa[i]);
        } else {
            ALUStandard::FullAdder(Gate_NOT(b[i]), pa[i], carry, out[i], carry);
        }
    }
    return out;
}