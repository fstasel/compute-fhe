#include <computefhe/ALUGateLogic.h>
#include <computefhe/ComputeFHE.h>

using namespace computefhe;

ALUGateLogic::ALUGateLogic(ComputeFHE *cfhe) : BaseALU(cfhe) {}

void ALUGateLogic::HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                             BinaryDigit &sum, BinaryDigit &carry_out) {
    auto &cc = cfhe_base->GetBinFHEContext();
    sum = cc.EvalBinGate(XOR, a, b);
    carry_out = cc.EvalBinGate(AND, a, b);
}

void ALUGateLogic::HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                                  BinaryDigit &sum, BinaryDigit &carry_out) {
    auto &cc = cfhe_base->GetBinFHEContext();
    sum = cc.EvalBinGate(XOR, a, b);
    carry_out = cc.EvalBinGate(OR, a, cc.EvalNOT(b));
}

void ALUGateLogic::FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                             const BinaryDigit &c, BinaryDigit &sum,
                             BinaryDigit &carry_out) {
    auto &cc = cfhe_base->GetBinFHEContext();
    BinaryDigit s = cc.EvalBinGate(XOR, a, b);
    BinaryDigit carry1 = cc.EvalBinGate(AND, a, b);
    BinaryDigit carry2 = cc.EvalBinGate(AND, s, c);
    sum = cc.EvalBinGate(XOR, s, c);
    carry_out = cc.EvalBinGate(OR, carry1, carry2);
}

BinaryDigit ALUGateLogic::XOR3(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c) {
    auto &cc = cfhe_base->GetBinFHEContext();
    BinaryDigit sum = cc.EvalBinGate(XOR, a, b);
    sum = cc.EvalBinGate(XOR, sum, c);
    return sum;
}

BinaryDigit ALUGateLogic::MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                                 const BinaryDigit &b, BinaryDigit *carry_out) {
    auto &cc = cfhe_base->GetBinFHEContext();
    BinaryDigit ma = cc.EvalBinGate(AND, m, a);
    BinaryDigit sum = cc.EvalBinGate(XOR, ma, b);
    if (carry_out) {
        *carry_out = cc.EvalBinGate(AND, ma, b);
    }
    return sum;
}

FixedPoint ALUGateLogic::Add(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUGateLogic::AddC(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        FullAdder(a[i], b[i], carry, out[i], carry);
    }
    return out;
}

FixedPoint ALUGateLogic::AddNC(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUGateLogic::Sub(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfSubtractor(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit inv_b = cc.EvalNOT(b[i]);
        FullAdder(a[i], inv_b, carry, out[i], carry);
    }
    return out;
}

FixedPoint ALUGateLogic::SubC(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        BinaryDigit inv = cc.EvalNOT(b[i]);
        FullAdder(a[i], inv, carry, out[i], carry);
    }
    return out;
}

FixedPoint ALUGateLogic::SubNC(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    HalfSubtractor(a[0], b[0], out[0], carry);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit inv_b = cc.EvalNOT(b[i]);
        if (i < n_digit - 1) {
            FullAdder(a[i], inv_b, carry, out[i], carry);
        } else {
            out[i] = XOR3(a[i], inv_b, carry);
        }
    }
    return out;
}

FixedPoint ALUGateLogic::Neg(const FixedPoint &a) {
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    out[0] = a[0];
    BinaryDigit c = cc.EvalNOT(a[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit inv = cc.EvalNOT(a[i]);
        if (i < n_digit - 1) {
            HalfAdder(inv, c, out[i], c);
        } else {
            out[i] = cc.EvalBinGate(XOR, inv, c);
        }
    }
    return out;
}

BinaryDigit ALUGateLogic::CmpNotEq(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    BinaryDigit out = cc.EvalBinGate(XOR, a[0], b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit eq = cc.EvalBinGate(XOR, a[i], b[i]);
        out = cc.EvalBinGate(OR, out, eq);
    }
    return out;
}

BinaryDigit ALUGateLogic::CmpEq(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    BinaryDigit out = cc.EvalBinGate(XNOR, a[0], b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit eq = cc.EvalBinGate(XNOR, a[i], b[i]);
        out = cc.EvalBinGate(AND, out, eq);
    }
    return out;
}

BinaryDigit ALUGateLogic::CmpLTEq_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    BinaryDigit inv_a = cc.EvalNOT(a[0]);
    BinaryDigit out = cc.EvalBinGate(OR, inv_a, b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_a = cc.EvalNOT(a[i]);
        BinaryDigit t1 = cc.EvalBinGate(AND, inv_a, b[i]);
        BinaryDigit t2 = cc.EvalBinGate(OR, inv_a, b[i]);
        out = cc.EvalBinGate(AND, t2, out);
        out = cc.EvalBinGate(OR, t1, out);
    }
    return out;
}

BinaryDigit ALUGateLogic::CmpGT_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    BinaryDigit inv_b = cc.EvalNOT(b[0]);
    BinaryDigit out = cc.EvalBinGate(AND, a[0], inv_b);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_b = cc.EvalNOT(b[i]);
        BinaryDigit t1 = cc.EvalBinGate(AND, a[i], inv_b);
        BinaryDigit t2 = cc.EvalBinGate(OR, a[i], inv_b);
        out = cc.EvalBinGate(AND, t2, out);
        out = cc.EvalBinGate(OR, t1, out);
    }
    return out;
}

BinaryDigit ALUGateLogic::CmpGTEq_U(const FixedPoint &a, const FixedPoint &b) {
    return CmpLTEq_U(b, a);
}

BinaryDigit ALUGateLogic::CmpLT_U(const FixedPoint &a, const FixedPoint &b) {
    return CmpGT_U(b, a);
}

BinaryDigit ALUGateLogic::CmpLTEq(const FixedPoint &a, const FixedPoint &b) {
    return CmpLTEq_U(ToggleMSB(a), ToggleMSB(b));
}

BinaryDigit ALUGateLogic::CmpGT(const FixedPoint &a, const FixedPoint &b) {
    return CmpGT_U(ToggleMSB(a), ToggleMSB(b));
}

BinaryDigit ALUGateLogic::CmpGTEq(const FixedPoint &a, const FixedPoint &b) {
    return CmpGTEq_U(ToggleMSB(a), ToggleMSB(b));
}

BinaryDigit ALUGateLogic::CmpLT(const FixedPoint &a, const FixedPoint &b) {
    return CmpLT_U(ToggleMSB(a), ToggleMSB(b));
}

FixedPoint ALUGateLogic::FullMul(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out((n_digit == 1) ? 1 : (n_digit << 1));
    for (uint8_t i = 0; i < n_digit; i++) {
        out[i] = cc.EvalBinGate(AND, a[i], b[0]);
    }
    for (uint8_t j = 1; j < n_digit; j++) {
        for (uint8_t i = 0; i < n_digit; i++) {
            BinaryDigit p = cc.EvalBinGate(AND, a[i], b[j]);
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

FixedPoint ALUGateLogic::Mul(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        out[i] = cc.EvalBinGate(AND, a[i], b[0]);
    }
    for (uint8_t j = 1; j < n_digit; j++) {
        for (uint8_t i = 0; i < n_digit - j; i++) {
            BinaryDigit p = cc.EvalBinGate(AND, a[i], b[j]);
            if (i == 0 && j < n_digit - 1) {
                HalfAdder(out[i + j], p, out[i + j], carry);
            } else if (i < n_digit - j - 1) {
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j < n_digit - 1) {
                out[i + j] = cc.EvalBinGate(XOR, out[i + j], carry);
                out[i + j] = cc.EvalBinGate(XOR, out[i + j], p);
            } else {
                out[i + j] = cc.EvalBinGate(XOR, out[i + j], p);
            }
        }
    }
    return out;
}

BinaryDigit ALUGateLogic::Mux(BinaryDigit s, BinaryDigit a, BinaryDigit b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(
        CMUX, vector({(LWECiphertext)a, (LWECiphertext)b, (LWECiphertext)s}));
}

void ALUGateLogic::Swap_if(const BinaryDigit cond, BinaryDigit &a,
                           BinaryDigit &b) {
    auto &cc = cfhe_base->GetBinFHEContext();
    BinaryDigit k = cc.EvalBinGate(AND, cc.EvalBinGate(XOR, a, b), cond);
    a = cc.EvalBinGate(XOR, a, k);
    b = cc.EvalBinGate(XOR, b, k);
}