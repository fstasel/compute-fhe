#include <computefhe/BaseArithmeticsEngine.h>
using namespace computefhe;

BaseArithmeticsEngine::BaseArithmeticsEngine(ComputeFHE *cfhe)
    : cfhe_base(cfhe) {
    ResetCarry();
}

BaseArithmeticsEngine::~BaseArithmeticsEngine() {}

LWECiphertext BaseArithmeticsEngine::GetCarry() { return carry; }

void BaseArithmeticsEngine::SetCarry(LWECiphertext value) {
    carry = COPY_CT(value);
}

void BaseArithmeticsEngine::SetCarry() { carry = GetConstantTrue(); }

void BaseArithmeticsEngine::ResetCarry() { carry = GetConstantFalse(); }

LWECiphertext BaseArithmeticsEngine::GetConstantFalse() {
    LWECiphertext constant_false =
        cfhe_base->GetBinFHEContext().EvalConstant(false);
    return COPY_CT(constant_false);
}

LWECiphertext BaseArithmeticsEngine::GetConstantTrue() {
    LWECiphertext constant_true =
        cfhe_base->GetBinFHEContext().EvalConstant(true);
    return COPY_CT(constant_true);
}

LWECiphertext
computefhe::BaseArithmeticsEngine::Gate_AND(ConstLWECiphertext &a,
                                            ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::AND, a, b);
}

LWECiphertext
computefhe::BaseArithmeticsEngine::Gate_NAND(ConstLWECiphertext &a,
                                             ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::NAND, a, b);
}

LWECiphertext
computefhe::BaseArithmeticsEngine::Gate_OR(ConstLWECiphertext &a,
                                           ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::OR, a, b);
}

LWECiphertext
computefhe::BaseArithmeticsEngine::Gate_NOR(ConstLWECiphertext &a,
                                            ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::NOR, a, b);
}

LWECiphertext
computefhe::BaseArithmeticsEngine::Gate_XOR(ConstLWECiphertext &a,
                                            ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::XOR, a, b);
}

LWECiphertext
computefhe::BaseArithmeticsEngine::Gate_XNOR(ConstLWECiphertext &a,
                                             ConstLWECiphertext &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::XNOR, a, b);
}

LWECiphertext
computefhe::BaseArithmeticsEngine::Gate_NOT(ConstLWECiphertext &a) {
    return cfhe_base->GetBinFHEContext().EvalNOT(a);
}

FixedPoint BaseArithmeticsEngine::ToggleMSB(const FixedPoint &a) {
    auto &cc = cfhe_base->GetBinFHEContext();
    FixedPoint t = FixedPoint(a);
    t.back() = cc.EvalNOT(t.back());
    return t;
}

FixedPoint BaseArithmeticsEngine::Mux(LWECiphertext s, const FixedPoint a,
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