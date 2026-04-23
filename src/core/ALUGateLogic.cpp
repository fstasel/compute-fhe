#include <computefhe/ALUGateLogic.h>
#include <computefhe/ComputeFHE.h>

using namespace computefhe;

ALUGateLogic::ALUGateLogic(ComputeFHE *cfhe) : BaseALU(cfhe) {}

BinaryDigit ALUGateLogic::Gate_MAJ(const BinaryDigit &a, const BinaryDigit &b,
                                   const BinaryDigit &c) {
    if (a.is_ct && b.is_ct && c.is_ct) {
        return Gate_OR(Gate_OR(Gate_AND(a, b), Gate_AND(a, c)), Gate_AND(b, c));
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

BinaryDigit ALUGateLogic::Gate_XOR3(const BinaryDigit &a, const BinaryDigit &b,
                                    const BinaryDigit &c) {
    BinaryDigit sum = Gate_XOR(a, b);
    sum = Gate_XOR(sum, c);
    return sum;
}

BinaryDigit ALUGateLogic::Gate_MulAdd(const BinaryDigit &m,
                                      const BinaryDigit &a,
                                      const BinaryDigit &b,
                                      BinaryDigit *carry_out) {
    BinaryDigit ma = Gate_AND(m, a);
    BinaryDigit sum = Gate_XOR(ma, b);
    if (carry_out) {
        *carry_out = Gate_AND(ma, b);
    }
    return sum;
}

BinaryDigit ALUGateLogic::Gate_DigitSum(const BinaryDigit &e1,
                                        const BinaryDigit &e0,
                                        const BinaryDigit &s0) {
    BinaryDigit t = Gate_AND(e0, Gate_NOT(s0));
    BinaryDigit s1 = Gate_XOR(e1, t);
    return s1;
}

FixedPoint ALUGateLogic::Mux(const BinaryDigit &s, const FixedPoint &a,
                             const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (size_t i = 0; i < n_digit; i++) {
        out[i] = Gate_MUX(s, a[i], b[i]);
    }
    return out;
}

FixedPoint ALUGateLogic::ToggleMSB(const FixedPoint &a) {
    FixedPoint t = FixedPoint(a);
    t.back() = Gate_NOT(t.back());
    return t;
}

FixedPoint ALUGateLogic::ShiftLeft(const FixedPoint &a, size_t shift) {
    int sz = (int)a.size();
    FixedPoint fp(a.size());
    int s = shift > a.size() ? a.size() : shift;
    for (int i = sz - 1; i >= 0; i--) {
        fp[i] = (i - s < 0) ? Constant0() : (BinaryDigit &)a[i - s];
    }
    return fp;
}

FixedPoint ALUGateLogic::ShiftRight(const FixedPoint &a, size_t shift,
                                    bool is_arithmetic) {
    int sz = (int)a.size();
    FixedPoint fp(a.size());
    int s = shift > a.size() ? a.size() : shift;
    for (int i = 0; i < sz; i++) {
        fp[i] = (i + s >= sz) ? (is_arithmetic ? (BinaryDigit &)a[a.size() - 1]
                                               : Constant0())
                              : (BinaryDigit &)a[i + s];
    }
    return fp;
}

void ALUGateLogic::Swap_if(const BinaryDigit &cond, BinaryDigit &a,
                           BinaryDigit &b) {
    BinaryDigit k = Gate_AND(Gate_XOR(a, b), cond);
    a = Gate_XOR(a, k);
    b = Gate_XOR(b, k);
}

void ALUGateLogic::Swap_if(const BinaryDigit &cond, FixedPoint &a,
                           FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    for (size_t i = 0; i < n_digit; i++) {
        Swap_if(cond, a[i], b[i]);
    }
}

void ALUGateLogic::HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                             BinaryDigit &sum, BinaryDigit &carry_out) {
    sum = Gate_XOR(a, b);
    carry_out = Gate_AND(a, b);
}

void ALUGateLogic::HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                                  BinaryDigit &sum, BinaryDigit &carry_out) {
    sum = Gate_XOR(a, b);
    carry_out = Gate_OR(a, Gate_NOT(b));
}

void ALUGateLogic::FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                             const BinaryDigit &c, BinaryDigit &sum,
                             BinaryDigit &carry_out) {
    if (a.is_ct && b.is_ct && c.is_ct) {
        // C-C-C
        BinaryDigit s = Gate_XOR(a, b);
        BinaryDigit carry1 = Gate_AND(a, b);
        BinaryDigit carry2 = Gate_AND(s, c);
        sum = Gate_XOR(s, c);
        carry_out = Gate_OR(carry1, carry2);
    } else if (!a.is_ct && !b.is_ct && !c.is_ct) {
        // P-P-P
        sum = (a.p + b.p + c.p) % 2 ? Constant1() : Constant0();
        carry_out = (a.p + b.p + c.p) >= 2 ? Constant1() : Constant0();
    } else {
        if (a.is_ct + b.is_ct + c.is_ct == 2) {
            // C-C-P
            BinaryDigit p, e1, e2;
            if (!a.is_ct) {
                p = a;
                e1 = b;
                e2 = c;
            } else if (!b.is_ct) {
                p = b;
                e1 = a;
                e2 = c;
            } else {
                p = c;
                e1 = a;
                e2 = b;
            }
            sum = Gate_XOR(p, Gate_XOR(e1, e2));
            carry_out = p.p ? Gate_OR(e1, e2) : Gate_AND(e1, e2);
        } else { // a.is_ct + b.is_ct + c.is_ct == 1
            // C-P-P
            BinaryDigit p1, p2, e;
            if (a.is_ct) {
                p1 = b;
                p2 = c;
                e = a;
            } else if (b.is_ct) {
                p1 = a;
                p2 = c;
                e = b;
            } else {
                p1 = a;
                p2 = b;
                e = c;
            }
            sum = (p1.p == p2.p) ? e : Gate_NOT(e);
            carry_out = (p1.p == p2.p) ? p1 : e;
        }
    }
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
            out[i] = Gate_XOR3(a[i], b[i], carry);
        }
    }
    return out;
}

FixedPoint ALUGateLogic::AddCNC(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        if (i < n_digit - 1) {
            FullAdder(a[i], b[i], carry, out[i], carry);
        } else {
            out[i] = Gate_XOR3(a[i], b[i], carry);
        }
    }
    return out;
}

FixedPoint ALUGateLogic::Sub(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUGateLogic::SubC(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUGateLogic::SubNC(const FixedPoint &a, const FixedPoint &b) {
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
            out[i] = Gate_XOR3(a[i], inv_b, carry);
        }
    }
    return out;
}

FixedPoint ALUGateLogic::Neg(const FixedPoint &a) {
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

BinaryDigit ALUGateLogic::CmpNotEq(const FixedPoint &a, const FixedPoint &b) {
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

BinaryDigit ALUGateLogic::CmpEq(const FixedPoint &a, const FixedPoint &b) {
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

BinaryDigit ALUGateLogic::CmpLTEq_U(const FixedPoint &a, const FixedPoint &b) {
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

BinaryDigit ALUGateLogic::CmpGT_U(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUGateLogic::Mul(const FixedPoint &a, const FixedPoint &b) {
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

void ALUGateLogic::DivU(const FixedPoint &a, const FixedPoint &b, FixedPoint &q,
                        FixedPoint &r) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    r = cfhe_base->GetConstantInt(0, n_digit);
    q = a;
    BinaryDigit c;
    FixedPoint t(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        c = q.back();
        q = ShiftLeft(q, 1);
        r = ShiftLeft(r, 1);
        r[0] = c;
        c = CmpLTEq_U(b, r);
        q[0] = c;
        for (uint8_t j = 0; j < n_digit; j++) {
            t[j] = Gate_AND(c, b[j]);
        }
        r = SubNC(r, t);
    }
}

FixedPoint ALUGateLogic::PAdd(const FixedPoint &a, const FixedPoint &pb) {
    return Add(a, pb);
}

FixedPoint ALUGateLogic::PAddC(const FixedPoint &a, const FixedPoint &pb) {
    return AddC(a, pb);
}

FixedPoint ALUGateLogic::PAddNC(const FixedPoint &a, const FixedPoint &pb) {
    return AddNC(a, pb);
}
