#include <computefhe/ALUStandard.h>
#include <computefhe/ComputeFHE.h>

using namespace computefhe;

ALUStandard::ALUStandard(ComputeFHE *cfhe) : BaseALU(cfhe) {}

BinaryDigit ALUStandard::Gate_MAJ(const BinaryDigit &a, const BinaryDigit &b,
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

BinaryDigit ALUStandard::Gate_XOR3(const BinaryDigit &a, const BinaryDigit &b,
                                   const BinaryDigit &c) {
    BinaryDigit sum = Gate_XOR(a, b);
    sum = Gate_XOR(sum, c);
    return sum;
}

BinaryDigit ALUStandard::Gate_MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                                     const BinaryDigit &b,
                                     BinaryDigit *carry_out) {
    BinaryDigit ma = Gate_AND(m, a);
    BinaryDigit sum = Gate_XOR(ma, b);
    if (carry_out) {
        *carry_out = Gate_AND(ma, b);
    }
    return sum;
}

BinaryDigit ALUStandard::Gate_DigitSum(const BinaryDigit &e1,
                                       const BinaryDigit &e0,
                                       const BinaryDigit &s0) {
    BinaryDigit t = Gate_AND(e0, Gate_NOT(s0));
    BinaryDigit s1 = Gate_XOR(e1, t);
    return s1;
}

FixedPoint ALUStandard::Mux(const BinaryDigit &s, const FixedPoint &a,
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

FixedPoint ALUStandard::ToggleMSB(const FixedPoint &a) {
    FixedPoint t = FixedPoint(a);
    t.back() = Gate_NOT(t.back());
    return t;
}

FixedPoint ALUStandard::ShiftLeft(const FixedPoint &a, size_t shift) {
    int sz = (int)a.size();
    FixedPoint fp(a.size());
    int s = shift > a.size() ? a.size() : shift;
    for (int i = sz - 1; i >= 0; i--) {
        fp[i] = (i - s < 0) ? Constant0() : (BinaryDigit &)a[i - s];
    }
    return fp;
}

FixedPoint ALUStandard::ShiftRight(const FixedPoint &a, size_t shift,
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

void ALUStandard::Swap_if(const BinaryDigit &cond, BinaryDigit &a,
                          BinaryDigit &b) {
    BinaryDigit k = Gate_AND(Gate_XOR(a, b), cond);
    a = Gate_XOR(a, k);
    b = Gate_XOR(b, k);
}

void ALUStandard::Swap_if(const BinaryDigit &cond, FixedPoint &a,
                          FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    for (size_t i = 0; i < n_digit; i++) {
        Swap_if(cond, a[i], b[i]);
    }
}

void ALUStandard::HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                            BinaryDigit &sum, BinaryDigit &carry_out) {
    BinaryDigit s = Gate_XOR(a, b);
    carry_out = Gate_AND(a, b);
    sum = s;
}

void ALUStandard::HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                                 BinaryDigit &sum, BinaryDigit &carry_out) {
    BinaryDigit s = Gate_XOR(a, b);
    carry_out = Gate_OR(a, Gate_NOT(b));
    sum = s;
}

void ALUStandard::FullAdder(const BinaryDigit &a, const BinaryDigit &b,
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
    } else if (a.is_ct + b.is_ct + c.is_ct == 2) {
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

FixedPoint ALUStandard::Add(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUStandard::AddC(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUStandard::AddNC(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUStandard::AddCNC(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUStandard::Sub(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUStandard::SubC(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUStandard::SubNC(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUStandard::SubCNC(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        BinaryDigit inv_b = Gate_NOT(b[i]);
        if (i < n_digit - 1) {
            FullAdder(a[i], inv_b, carry, out[i], carry);
        } else {
            out[i] = Gate_XOR3(a[i], inv_b, carry);
        }
    }
    return out;
}

FixedPoint ALUStandard::Neg(const FixedPoint &a) {
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

FixedPoint ALUStandard::Not(const FixedPoint &a) {
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        out[i] = Gate_NOT(a[i]);
    }
    return out;
}

BinaryDigit ALUStandard::CmpNotEq(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    // Auto-reduced while comparing plaintext
    BinaryDigit out = Gate_XOR(a[0], b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit eq = Gate_XOR(a[i], b[i]);
        out = Gate_OR(out, eq);
    }
    return out;
}

BinaryDigit ALUStandard::CmpEq(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    // Auto-reduced while comparing plaintext
    BinaryDigit out = Gate_XNOR(a[0], b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        BinaryDigit eq = Gate_XNOR(a[i], b[i]);
        out = Gate_AND(out, eq);
    }
    return out;
}

BinaryDigit ALUStandard::CmpLTEq_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    // Auto-reduced while comparing plaintext
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

BinaryDigit ALUStandard::CmpGT_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    // Auto-reduced while comparing plaintext
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

BinaryDigit ALUStandard::CmpGTEq_U(const FixedPoint &a, const FixedPoint &b) {
    return CmpLTEq_U(b, a);
}

BinaryDigit ALUStandard::CmpLT_U(const FixedPoint &a, const FixedPoint &b) {
    return CmpGT_U(b, a);
}

BinaryDigit ALUStandard::CmpLTEq(const FixedPoint &a, const FixedPoint &b) {
    return CmpLTEq_U(ToggleMSB(a), ToggleMSB(b));
}

BinaryDigit ALUStandard::CmpGT(const FixedPoint &a, const FixedPoint &b) {
    return CmpGT_U(ToggleMSB(a), ToggleMSB(b));
}

BinaryDigit ALUStandard::CmpGTEq(const FixedPoint &a, const FixedPoint &b) {
    return CmpGTEq_U(ToggleMSB(a), ToggleMSB(b));
}

BinaryDigit ALUStandard::CmpLT(const FixedPoint &a, const FixedPoint &b) {
    return CmpLT_U(ToggleMSB(a), ToggleMSB(b));
}

FixedPoint ALUStandard::FullMul(const FixedPoint &a, const FixedPoint &b) {
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

FixedPoint ALUStandard::Mul(const FixedPoint &a, const FixedPoint &b) {
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

void ALUStandard::DivU(const FixedPoint &a, const FixedPoint &b, FixedPoint &q,
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

FixedPoint ALUStandard::PAdd(const FixedPoint &a, const FixedPoint &pb) {
    return Add(a, pb);
}

FixedPoint ALUStandard::PAddC(const FixedPoint &a, const FixedPoint &pb) {
    return AddC(a, pb);
}

FixedPoint ALUStandard::PAddNC(const FixedPoint &a, const FixedPoint &pb) {
    return AddNC(a, pb);
}

FixedPoint ALUStandard::PAddCNC(const FixedPoint &a, const FixedPoint &pb) {
    return AddCNC(a, pb);
}

FixedPoint ALUStandard::PSub(const FixedPoint &pa, const FixedPoint &b) {
    return Sub(pa, b);
}

FixedPoint ALUStandard::PSubC(const FixedPoint &pa, const FixedPoint &b) {
    return SubC(pa, b);
}

FixedPoint ALUStandard::PSubNC(const FixedPoint &pa, const FixedPoint &b) {
    return SubNC(pa, b);
}

FixedPoint ALUStandard::PSubCNC(const FixedPoint &pa, const FixedPoint &b) {
    return SubCNC(pa, b);
}

FixedPoint ALUStandard::CPSub(const FixedPoint &a, const FixedPoint &pb) {
    return PAdd(a, Neg(pb));
}

FixedPoint ALUStandard::CPSubC(const FixedPoint &a, const FixedPoint &pb) {
    return PAddC(a, Not(pb));
}

FixedPoint ALUStandard::CPSubNC(const FixedPoint &a, const FixedPoint &pb) {
    return PAddNC(a, Neg(pb));
}

FixedPoint ALUStandard::CPSubCNC(const FixedPoint &a, const FixedPoint &pb) {
    return PAddCNC(a, Not(pb));
}

FixedPoint ALUStandard::PFullMul(const FixedPoint &a, const FixedPoint &pb) {
    FixedPoint out, acc;
    uint num_zeros = 0;
    if (a.size() == 0 || pb.size() == 0) {
        out.push_back(Constant0());
        return out;
    }
    for (size_t i = 0; i < pb.size(); i++) {
        if (pb[i].p == 0) {
            if (acc.size() == 0) {
                num_zeros++;
            } else {
                out.push_back(acc.front());
                acc.erase(acc.begin());
            }
        } else if (acc.size() == 0) {
            for (size_t j = 0; j < num_zeros; j++) {
                out.push_back(Constant0());
            }
            num_zeros = 0;
            out.push_back(a[0]);
            for (size_t j = 1; j < a.size(); j++) {
                acc.push_back(a[j]);
            }
        } else {
            size_t s = acc.size();
            acc = Add(acc, FixedPoint(a.begin(), a.begin() + s));
            out.push_back(acc.front());
            acc.erase(acc.begin());
            if (a.size() > s) {
                FixedPoint sum = AddC(
                    FixedPoint(a.begin() + s, a.end()),
                    FixedPoint(vector<BinaryDigit>(a.size() - s, Constant0())));
                for (size_t j = 0; j < sum.size(); j++) {
                    acc.push_back(sum[j]);
                }
            }
            acc.push_back(carry);
        }
    }
    for (size_t j = 0; j < acc.size(); j++) {
        out.push_back(acc[j]);
    }
    if (out.size() == 0) {
        out.push_back(Constant0());
    }
    return out;
}

FixedPoint ALUStandard::PFullMulFast(const FixedPoint &a,
                                     const FixedPoint &pb) {
    return PFullMul(a, pb);
}

FixedPoint ALUStandard::PBoothsMul(const FixedPoint &a, const FixedPoint &pb) {
    return PFullMul(a, pb);
}

FixedPoint ALUStandard::PMul(const FixedPoint &a, const FixedPoint &pb) {
    if (a.size() == 0 || pb.size() == 0 ||
        cfhe_base->ConvertConstantInt(pb) == 0) {
        FixedPoint zero(1);
        zero[0] = Constant0();
        return zero;
    }
    if (a.size() != pb.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (size_t i = 0; i < n_digit; i++) {
        out[i] = Constant0();
    }
    bool acc = false;
    for (size_t i = 0; i < n_digit; i++) {
        if (pb[i].p == 1 && !acc) {
            for (size_t j = i; j < n_digit; j++) {
                out[j] = a[j - i];
            }
            acc = true;
        } else if (pb[i].p == 1 && acc) {
            FixedPoint r = AddNC(FixedPoint(a.begin(), a.begin() + n_digit - i),
                                 FixedPoint(out.begin() + i, out.end()));
            for (size_t j = 0; j < r.size(); j++) {
                out[i + j] = r[j];
            }
        }
    }
    return out;
}

FixedPoint ALUStandard::PMulFast(const FixedPoint &a, const FixedPoint &pb) {
    return PMul(a, pb);
}

uint ALUStandard::Get_CtCtAdd_Cost(size_t n_bits) { return 0; }
uint ALUStandard::Get_CtCtAddNC_Cost(size_t n_bits) { return 0; }
uint ALUStandard::Get_CtCtSubC_Cost(size_t n_bits) { return 0; }
uint ALUStandard::Get_CtCtSubNC_Cost(size_t n_bits) { return 0; }
uint ALUStandard::Get_CtPtAddC_Cost(size_t n_bits) { return 0; }
uint ALUStandard::Get_PtCtSub_Cost(size_t n_bits) { return 0; }
uint ALUStandard::Get_CtPtSubCNC_Cost(size_t n_bits) { return 0; }
uint ALUStandard::Get_CtNeg_Cost(size_t n_bits) { return 0; }
uint ALUStandard::Get_PtFullMul_Cost(const FixedPoint &pt, size_t ct_n_bits,
                                     size_t &out_n_bits) {
    return 0;
}
uint ALUStandard::Get_Pt2sCompFullMul_Cost(const FixedPoint &pt,
                                           size_t ct_n_bits) {
    return 0;
}
uint ALUStandard::Get_PtMul_Cost(const FixedPoint &pt) { return 0; }
uint ALUStandard::Get_Pt2sCompMul_Cost(const FixedPoint &pt) { return 0; }
uint ALUStandard::Get_BoothsMul_Cost(const FixedPoint &pt, size_t ct_n_bits) {
    return 0;
}