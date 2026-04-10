#include <computefhe/ALUOptimized.h>
using namespace computefhe;

ALUOptimized::ALUOptimized(ComputeFHE *cfhe) : ALUGateLogic(cfhe) {}

void ALUOptimized::FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                             const BinaryDigit &c, BinaryDigit &sum,
                             BinaryDigit &carry_out) {
    auto &cc = cfhe_base->GetBinFHEContext();
    BinaryDigit s = XOR3(a, b, c);
    carry_out = cc.EvalBinGate(
        MAJORITY, {(LWECiphertext)a, (LWECiphertext)b, (LWECiphertext)c});
    sum = s;
}

BinaryDigit ALUOptimized::XOR3(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c) {
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    BinaryDigit sum = a;
    lwe->EvalAddEq(sum, b);
    sum = cc.EvalBinGate(XOR, sum, c);
    return sum;
}

BinaryDigit ALUOptimized::MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                                 const BinaryDigit &b, BinaryDigit *carry_out) {
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

BinaryDigit ALUOptimized::CmpLTEq_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    BinaryDigit inv_a = cc.EvalNOT(a[0]);
    BinaryDigit c = cc.EvalBinGate(OR, inv_a, b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_a = cc.EvalNOT(a[i]);
        c = cc.EvalBinGate(MAJORITY, {inv_a, b[i], c});
    }
    return c;
}

BinaryDigit ALUOptimized::CmpGT_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    BinaryDigit inv_b = cc.EvalNOT(b[0]);
    BinaryDigit c = cc.EvalBinGate(AND, a[0], inv_b);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_b = cc.EvalNOT(b[i]);
        c = cc.EvalBinGate(MAJORITY, {a[i], inv_b, c});
    }
    return c;
}

FixedPoint ALUOptimized::FullMul(const FixedPoint &a, const FixedPoint &b) {
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
            if (i == 0) {
                out[i + j] = MulAdd(a[i], b[j], out[i + j], &carry);
            } else if (i < n_digit - 1) {
                BinaryDigit p = cc.EvalBinGate(AND, a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j == 1) {
                out[i + j] =
                    MulAdd(a[i], b[j], carry, &(BinaryDigit &)out[i + j + 1]);
            } else {
                BinaryDigit p = cc.EvalBinGate(AND, a[i], b[j]);
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
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (uint8_t i = 0; i < n_digit; i++) {
        out[i] = cc.EvalBinGate(AND, a[i], b[0]);
    }
    for (uint8_t j = 1; j < n_digit; j++) {
        for (uint8_t i = 0; i < n_digit - j; i++) {
            if (i == 0 && j < n_digit - 1) {
                out[i + j] = MulAdd(a[i], b[j], out[i + j], &carry);
            } else if (i < n_digit - j - 1) {
                BinaryDigit p = cc.EvalBinGate(AND, a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j < n_digit - 1) {
                BinaryDigit p = cc.EvalBinGate(AND, a[i], b[j]);
                out[i + j] = XOR3(out[i + j], carry, p);
            } else {
                out[i + j] = MulAdd(a[i], b[j], out[i + j]);
            }
        }
    }
    return out;
}

BinaryDigit ALUOptimized::Mux(BinaryDigit s, BinaryDigit a, BinaryDigit b) {
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    BinaryDigit t = cc.EvalBinGate(OR, s, a);
    lwe->EvalAddEq(t, t);
    lwe->EvalSubEq(t, b);
    return cc.EvalBinGate(OR, s, t);
}