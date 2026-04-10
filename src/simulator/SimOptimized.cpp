#include <computefhe/SimOptimized.h>
using namespace computefhe;

#define GATE_MAJ(a, b, c)                                                      \
    (((LWEPlaintext)a + (LWEPlaintext)b + (LWEPlaintext)c) > 1 ? 1 : 0)

SimOptimized::SimOptimized(ComputeFHE *cfhe) : SimGateLogic(cfhe) {}

void SimOptimized::FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                             const BinaryDigit &c, BinaryDigit &sum,
                             BinaryDigit &carry_out) {
    BinaryDigit s = XOR3(a, b, c);
    carry_out = GATE_MAJ(a, b, c);
    sum = s;
    num_bs++;
    num_maj++;
}

BinaryDigit SimOptimized::XOR3(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c) {
    num_bs++;
    num_xor3++;
    return BinaryDigit(a.p ^ b.p ^ c.p);
}

BinaryDigit SimOptimized::MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                                 const BinaryDigit &b, BinaryDigit *carry_out) {
    BinaryDigit ma = (m.p & a.p) ^ b.p;
    if (carry_out) {
        num_bs += 2;
        num_mac++;
        *carry_out = m.p & b.p & a.p;
    } else {
        num_bs++;
        num_ma++;
    }
    return ma;
}

BinaryDigit SimOptimized::CmpLTEq_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    BinaryDigit inv_a = Gate_NOT(a[0]);
    BinaryDigit c = Gate_OR(inv_a, b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_a = Gate_NOT(a[i]);
        c = GATE_MAJ(inv_a, b[i], c);
        num_bs++;
        num_maj++;
    }
    return c;
}

BinaryDigit SimOptimized::CmpGT_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    BinaryDigit inv_b = Gate_NOT(b[0]);
    BinaryDigit c = Gate_AND(a[0], inv_b);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_b = Gate_NOT(b[i]);
        c = GATE_MAJ(a[i], inv_b, c);
        num_bs++;
        num_maj++;
    }
    return c;
}

FixedPoint SimOptimized::FullMul(const FixedPoint &a, const FixedPoint &b) {
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
                out[i + j] = MulAdd(a[i], b[j], out[i + j], &carry);
            } else if (i < n_digit - 1) {
                BinaryDigit p = Gate_AND(a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j == 1) {
                out[i + j] =
                    MulAdd(a[i], b[j], carry, &(BinaryDigit &)out[i + j + 1]);
            } else {
                BinaryDigit p = Gate_AND(a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], out[i + j + 1]);
            }
        }
    }
    return out;
}

FixedPoint SimOptimized::Mul(const FixedPoint &a, const FixedPoint &b) {
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
                out[i + j] = MulAdd(a[i], b[j], out[i + j], &carry);
            } else if (i < n_digit - j - 1) {
                BinaryDigit p = Gate_AND(a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j < n_digit - 1) {
                BinaryDigit p = Gate_AND(a[i], b[j]);
                out[i + j] = XOR3(out[i + j], carry, p);
            } else {
                out[i + j] = MulAdd(a[i], b[j], out[i + j]);
            }
        }
    }
    return out;
}

BinaryDigit SimOptimized::Mux(BinaryDigit s, BinaryDigit a, BinaryDigit b) {
    num_bs += 2;
    num_mux++;
    return BinaryDigit(((LWEPlaintext)s == 0 ? a : b).p);
}

void SimOptimized::Swap_if(const BinaryDigit cond, BinaryDigit &a,
                           BinaryDigit &b) {
    BinaryDigit t = a;
    a = Mux(cond, t, b);
    b = XOR3(a, b, t);
}

#undef GATE_MAJ