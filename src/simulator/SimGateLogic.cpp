#include <computefhe/SimGateLogic.h>
using namespace computefhe;

SimGateLogic::SimGateLogic(ComputeFHE *cfhe) : BaseALUSimulator(cfhe) {}

void SimGateLogic::HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                             BinaryDigit &sum, BinaryDigit &carry_out) {
    sum = Gate_XOR(a, b);
    carry_out = Gate_AND(a, b);
}

void SimGateLogic::HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                                  BinaryDigit &sum, BinaryDigit &carry_out) {
    sum = Gate_XOR(a, b);
    carry_out = Gate_OR(a, Gate_NOT(b));
}

void SimGateLogic::FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                             const BinaryDigit &c, BinaryDigit &sum,
                             BinaryDigit &carry_out) {
    BinaryDigit s = Gate_XOR(a, b);
    BinaryDigit carry1 = Gate_AND(a, b);
    BinaryDigit carry2 = Gate_AND(s, c);
    sum = Gate_XOR(s, c);
    carry_out = Gate_OR(carry1, carry2);
}

BinaryDigit SimGateLogic::XOR3(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c) {
    BinaryDigit sum = Gate_XOR(a, b);
    sum = Gate_XOR(sum, c);
    return sum;
}

BinaryDigit SimGateLogic::MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                                 const BinaryDigit &b, BinaryDigit *carry_out) {
    BinaryDigit ma = Gate_AND(m, a);
    BinaryDigit sum = Gate_XOR(ma, b);
    if (carry_out) {
        *carry_out = Gate_AND(ma, b);
    }
    return sum;
}

FixedPoint SimGateLogic::Add(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfAdder(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        FullAdder(a[i], b[i], carry, out[i], carry);
    }
    return out;
}

FixedPoint SimGateLogic::AddC(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    FullAdder(a[0], b[0], carry, out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        FullAdder(a[i], b[i], carry, out[i], carry);
    }
    return out;
}

FixedPoint SimGateLogic::AddNC(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfAdder(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        if (i < n_digit - 1) {
            FullAdder(a[i], b[i], carry, out[i], carry);
        } else {
            out[i] = XOR3(a[i], b[i], carry);
        }
    }
    return out;
}

FixedPoint SimGateLogic::Sub(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfSubtractor(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit inv_b = Gate_NOT(b[i]);
        FullAdder(a[i], inv_b, carry, out[i], carry);
    }
    return out;
}

FixedPoint SimGateLogic::SubC(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        BinaryDigit inv = Gate_NOT(b[i]);
        FullAdder(a[i], inv, carry, out[i], carry);
    }
    return out;
}

FixedPoint SimGateLogic::SubNC(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfSubtractor(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit inv_b = Gate_NOT(b[i]);
        if (i < n_digit - 1) {
            FullAdder(a[i], inv_b, carry, out[i], carry);
        } else {
            out[i] = XOR3(a[i], inv_b, carry);
        }
    }
    return out;
}

FixedPoint SimGateLogic::Neg(const FixedPoint &a) {
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    out[0] = a[0];
    BinaryDigit c = Gate_NOT(a[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit inv = Gate_NOT(a[i]);
        if (i < n_digit - 1) {
            HalfAdder(inv, c, out[i], c);
        } else {
            out[i] = Gate_XOR(inv, c);
        }
    }
    return out;
}

BinaryDigit SimGateLogic::CmpNotEq(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    BinaryDigit out = Gate_XOR(a[0], b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit eq = Gate_XOR(a[i], b[i]);
        out = Gate_OR(out, eq);
    }
    return out;
}

BinaryDigit SimGateLogic::CmpEq(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    BinaryDigit out = Gate_XNOR(a[0], b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit eq = Gate_XNOR(a[i], b[i]);
        out = Gate_AND(out, eq);
    }
    return out;
}

BinaryDigit SimGateLogic::CmpLTEq_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    BinaryDigit inv_a = Gate_NOT(a[0]);
    BinaryDigit out = Gate_OR(inv_a, b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_a = Gate_NOT(a[i]);
        BinaryDigit t1 = Gate_AND(inv_a, b[i]);
        BinaryDigit t2 = Gate_OR(inv_a, b[i]);
        out = Gate_AND(t2, out);
        out = Gate_OR(t1, out);
    }
    return out;
}

BinaryDigit SimGateLogic::CmpGT_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    BinaryDigit inv_b = Gate_NOT(b[0]);
    BinaryDigit out = Gate_AND(a[0], inv_b);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_b = Gate_NOT(b[i]);
        BinaryDigit t1 = Gate_AND(a[i], inv_b);
        BinaryDigit t2 = Gate_OR(a[i], inv_b);
        out = Gate_AND(t2, out);
        out = Gate_OR(t1, out);
    }
    return out;
}

BinaryDigit SimGateLogic::CmpGTEq_U(const FixedPoint &a, const FixedPoint &b) {
    return CmpLTEq_U(b, a);
}

BinaryDigit SimGateLogic::CmpLT_U(const FixedPoint &a, const FixedPoint &b) {
    return CmpGT_U(b, a);
}

BinaryDigit SimGateLogic::CmpLTEq(const FixedPoint &a, const FixedPoint &b) {
    return CmpLTEq_U(ToggleMSB(a), ToggleMSB(b));
}

BinaryDigit SimGateLogic::CmpGT(const FixedPoint &a, const FixedPoint &b) {
    return CmpGT_U(ToggleMSB(a), ToggleMSB(b));
}

BinaryDigit SimGateLogic::CmpGTEq(const FixedPoint &a, const FixedPoint &b) {
    return CmpGTEq_U(ToggleMSB(a), ToggleMSB(b));
}

BinaryDigit SimGateLogic::CmpLT(const FixedPoint &a, const FixedPoint &b) {
    return CmpLT_U(ToggleMSB(a), ToggleMSB(b));
}

FixedPoint SimGateLogic::FullMul(const FixedPoint &a, const FixedPoint &b) {
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
            BinaryDigit p = Gate_AND(a[i], b[j]);
            if (i == 0) {
                HalfAdder(out[i + j], p, out[i + j], carry);
            } else if (i < n_digit - 1) {
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j == 1) {
                HalfAdder(p, carry, out[i + j], out[i + j + 1]);
            } else {
                FullAdder(out[i + j], p, carry, out[i + j], out[i + j + 1]);
            }
        }
    }
    return out;
}

FixedPoint SimGateLogic::Mul(const FixedPoint &a, const FixedPoint &b) {
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
            BinaryDigit p = Gate_AND(a[i], b[j]);
            if (i == 0 && j < n_digit - 1) {
                HalfAdder(out[i + j], p, out[i + j], carry);
            } else if (i < n_digit - j - 1) {
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j < n_digit - 1) {
                out[i + j] = Gate_XOR(out[i + j], carry);
                out[i + j] = Gate_XOR(out[i + j], p);
            } else {
                out[i + j] = Gate_XOR(out[i + j], p);
            }
        }
    }
    return out;
}

BinaryDigit SimGateLogic::Mux(BinaryDigit s, BinaryDigit a, BinaryDigit b) {
    return Gate_NAND(Gate_NAND(Gate_NOT(s), a), Gate_NAND(s, b));
}

void SimGateLogic::Swap_if(const BinaryDigit cond, BinaryDigit &a,
                           BinaryDigit &b) {
    BinaryDigit k = Gate_AND(Gate_XOR(a, b), cond);
    a = Gate_XOR(a, k);
    b = Gate_XOR(b, k);
}