#include <computefhe/AEOptimized.h>
using namespace computefhe;

AEOptimized::AEOptimized(ComputeFHE *cfhe) : AEGateLogic(cfhe) {}

void AEOptimized::FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                            ConstLWECiphertext &c, LWECiphertext &sum,
                            LWECiphertext &carry_out) {
    LWECiphertext _a = COPY_CT(a);
    LWECiphertext _b = COPY_CT(b);
    LWECiphertext _c = COPY_CT(c);
    auto &cc = cfhe_base->GetBinFHEContext();
    sum = XOR3(_a, _b, _c);
    carry_out = cc.EvalBinGate(MAJORITY, {_a, _b, _c});
}

LWECiphertext AEOptimized::XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b,
                                ConstLWECiphertext &c) {
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    LWECiphertext sum = COPY_CT(a);
    lwe->EvalAddEq(sum, b);
    sum = cc.EvalBinGate(XOR, sum, c);
    return sum;
}

LWECiphertext AEOptimized::MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a,
                                  ConstLWECiphertext &b,
                                  LWECiphertext *carry_out) {
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    LWECiphertext a_2b = COPY_CT(b);
    lwe->EvalAddEq(a_2b, a_2b);
    lwe->EvalAddEq(a_2b, a);
    LWECiphertext ma_2b = cc.EvalBinGate(AND, m, a_2b);
    if (carry_out) {
        LWECiphertext neg_b = COPY_CT(b);
        lwe->EvalMultConstEq(neg_b, -1);
        *carry_out = cc.EvalBinGate(AND, ma_2b, neg_b);
    }
    return ma_2b;
}

LWECiphertext AEOptimized::CmpLTEq_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    LWECiphertext inv_a = cc.EvalNOT(a[0]);
    LWECiphertext c = cc.EvalBinGate(OR, inv_a, b[0]);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_a = cc.EvalNOT(a[i]);
        c = cc.EvalBinGate(MAJORITY, {inv_a, b[i], c});
    }
    return c;
}

LWECiphertext AEOptimized::CmpGT_U(const FixedPoint &a, const FixedPoint &b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    auto &cc = cfhe_base->GetBinFHEContext();
    size_t n_digit = a.size();

    LWECiphertext inv_b = cc.EvalNOT(b[0]);
    LWECiphertext c = cc.EvalBinGate(AND, a[0], inv_b);
    for (uint8_t i = 1; i < n_digit; i++) {
        inv_b = cc.EvalNOT(b[i]);
        c = cc.EvalBinGate(MAJORITY, {a[i], inv_b, c});
    }
    return c;
}

FixedPoint AEOptimized::FullMul(const FixedPoint &a, const FixedPoint &b) {
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
                LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j == 1) {
                out[i + j] = MulAdd(a[i], b[j], carry, &out[i + j + 1]);
            } else {
                LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], out[i + j + 1]);
            }
        }
    }
    return out;
}

FixedPoint AEOptimized::Mul(const FixedPoint &a, const FixedPoint &b) {
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
                LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
                FullAdder(out[i + j], p, carry, out[i + j], carry);
            } else if (j < n_digit - 1) {
                LWECiphertext p = cc.EvalBinGate(AND, a[i], b[j]);
                out[i + j] = XOR3(out[i + j], carry, p);
            } else {
                out[i + j] = MulAdd(a[i], b[j], out[i + j]);
            }
        }
    }
    return out;
}

LWECiphertext AEOptimized::Mux(LWECiphertext s, LWECiphertext a,
                               LWECiphertext b) {
    auto &cc = cfhe_base->GetBinFHEContext();
    auto &lwe = cc.GetLWEScheme();
    LWECiphertext t = cc.EvalBinGate(OR, s, a);
    lwe->EvalAddEq(t, t);
    lwe->EvalSubEq(t, b);
    return cc.EvalBinGate(OR, s, t);
}