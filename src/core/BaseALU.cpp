#include <computefhe/BaseALU.h>
#include <computefhe/ComputeFHE.h>

using namespace computefhe;

BaseALU::BaseALU(ComputeFHE *cfhe) : cfhe_base(cfhe) { ResetCarry(); }

BaseALU::~BaseALU() {}

BinaryDigit BaseALU::GetCarry() { return carry; }

void BaseALU::SetCarry(BinaryDigit value) { carry = value; }

void BaseALU::SetCarry() { carry = GetConstantTrue(); }

void BaseALU::ResetCarry() { carry = GetConstantFalse(); }

BinaryDigit BaseALU::GetConstantFalse() {
    BinaryDigit constant_false =
        cfhe_base->GetBinFHEContext().EvalConstant(false);
    return constant_false;
}

BinaryDigit BaseALU::GetConstantTrue() {
    BinaryDigit constant_true =
        cfhe_base->GetBinFHEContext().EvalConstant(true);
    return constant_true;
}

BinaryDigit computefhe::BaseALU::Gate_AND(const BinaryDigit &a,
                                          const BinaryDigit &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::AND, a, b);
}

BinaryDigit computefhe::BaseALU::Gate_NAND(const BinaryDigit &a,
                                           const BinaryDigit &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::NAND, a, b);
}

BinaryDigit computefhe::BaseALU::Gate_OR(const BinaryDigit &a,
                                         const BinaryDigit &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::OR, a, b);
}

BinaryDigit computefhe::BaseALU::Gate_NOR(const BinaryDigit &a,
                                          const BinaryDigit &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::NOR, a, b);
}

BinaryDigit computefhe::BaseALU::Gate_XOR(const BinaryDigit &a,
                                          const BinaryDigit &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::XOR, a, b);
}

BinaryDigit computefhe::BaseALU::Gate_XNOR(const BinaryDigit &a,
                                           const BinaryDigit &b) {
    return cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::XNOR, a, b);
}

BinaryDigit computefhe::BaseALU::Gate_NOT(const BinaryDigit &a) {
    return cfhe_base->GetBinFHEContext().EvalNOT(a);
}

FixedPoint BaseALU::ToggleMSB(const FixedPoint &a) {
    auto &cc = cfhe_base->GetBinFHEContext();
    FixedPoint t = FixedPoint(a);
    t.back() = cc.EvalNOT(t.back());
    return t;
}

FixedPoint BaseALU::ShiftLeft(const FixedPoint &a, size_t shift) {
    int sz = (int)a.size();
    FixedPoint fp(a.size());
    int s = shift > a.size() ? a.size() : shift;
    for (int i = sz - 1; i >= 0; i--) {
        fp[i] = (i - s < 0) ? GetConstantFalse() : (BinaryDigit &)a[i - s];
    }
    return fp;
}

FixedPoint BaseALU::ShiftRight(const FixedPoint &a, size_t shift,
                               bool is_arithmetic) {
    int sz = (int)a.size();
    FixedPoint fp(a.size());
    int s = shift > a.size() ? a.size() : shift;
    for (int i = 0; i < sz; i++) {
        fp[i] = (i + s >= sz) ? (is_arithmetic ? (BinaryDigit &)a[a.size() - 1]
                                               : GetConstantFalse())
                              : (BinaryDigit &)a[i + s];
    }
    return fp;
}

FixedPoint BaseALU::Mux(BinaryDigit s, const FixedPoint a, const FixedPoint b) {
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