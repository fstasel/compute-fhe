#include <computefhe/BaseALU.h>
using namespace computefhe;

BaseALU::BaseALU(ComputeFHE *cfhe) : cfhe_base(cfhe) { ResetCarry(); }

BaseALU::~BaseALU() {}

LWECiphertext BaseALU::GetCarry() { return carry; }

void BaseALU::SetCarry(LWECiphertext value) { carry = COPY_CT(value); }

void BaseALU::SetCarry() { carry = GetConstantTrue(); }

void BaseALU::ResetCarry() { carry = GetConstantFalse(); }

LWECiphertext BaseALU::GetConstantFalse() {
    LWECiphertext constant_false =
        cfhe_base->GetBinFHEContext().EvalConstant(false);
    return COPY_CT(constant_false);
}

LWECiphertext BaseALU::GetConstantTrue() {
    LWECiphertext constant_true =
        cfhe_base->GetBinFHEContext().EvalConstant(true);
    return COPY_CT(constant_true);
}

LWECiphertext computefhe::BaseALU::Gate_AND(ConstLWECiphertext &a,
                                            ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::AND, a, b);
}

LWECiphertext computefhe::BaseALU::Gate_NAND(ConstLWECiphertext &a,
                                             ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::NAND, a, b);
}

LWECiphertext computefhe::BaseALU::Gate_OR(ConstLWECiphertext &a,
                                           ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::OR, a, b);
}

LWECiphertext computefhe::BaseALU::Gate_NOR(ConstLWECiphertext &a,
                                            ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::NOR, a, b);
}

LWECiphertext computefhe::BaseALU::Gate_XOR(ConstLWECiphertext &a,
                                            ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::XOR, a, b);
}

LWECiphertext computefhe::BaseALU::Gate_XNOR(ConstLWECiphertext &a,
                                             ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::XNOR, a, b);
}

LWECiphertext computefhe::BaseALU::Gate_NOT(ConstLWECiphertext &a) {
    return cfhe_base->GetBinFHEContext().EvalNOT(a);
}

FixedPoint BaseALU::ToggleMSB(const FixedPoint &a) {
    auto &cc = cfhe_base->GetBinFHEContext();
    FixedPoint t = FixedPoint(a);
    t.back() = cc.EvalNOT(t.back());
    return t;
}

FixedPoint BaseALU::Mux(LWECiphertext s, const FixedPoint a,
                        const FixedPoint b) {
    if (a.size() != b.size()) {
        OPENFHE_THROW("Input numbers should be of the same bit length.");
    }
    size_t n_digit = a.size();

    FixedPoint out(n_digit);
    for (size_t i = 0; i < n_digit; i++) {
        out[i] = Mux(s, a[i], b[i]);
    }
    return out;
}