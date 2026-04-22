#include <computefhe/BaseALU.h>
#include <computefhe/ComputeFHE.h>

using namespace computefhe;

BaseALU::BaseALU(ComputeFHE *cfhe) : cfhe_base(cfhe) { ResetCarry(); }

BaseALU::~BaseALU() {}

BinaryDigit BaseALU::GetCarry() { return carry; }

void BaseALU::SetCarry(BinaryDigit value) { carry = value; }

void BaseALU::SetCarry() { carry = Constant1(); }

void BaseALU::ResetCarry() { carry = Constant0(); }

BinaryDigit BaseALU::FHE_False() {
    return BinaryDigit(cfhe_base->GetBinFHEContext().EvalConstant(false));
}

BinaryDigit BaseALU::FHE_True() {
    return BinaryDigit(cfhe_base->GetBinFHEContext().EvalConstant(true));
}

BinaryDigit BaseALU::FHE_AND(const BinaryDigit &a, const BinaryDigit &b) {
    return BinaryDigit(
        cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::AND, a.c, b.c));
}

BinaryDigit BaseALU::FHE_NAND(const BinaryDigit &a, const BinaryDigit &b) {
    return BinaryDigit(
        cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::NAND, a.c, b.c));
}

BinaryDigit BaseALU::FHE_OR(const BinaryDigit &a, const BinaryDigit &b) {
    return BinaryDigit(
        cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::OR, a.c, b.c));
}

BinaryDigit BaseALU::FHE_NOR(const BinaryDigit &a, const BinaryDigit &b) {
    return BinaryDigit(
        cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::NOR, a.c, b.c));
}

BinaryDigit BaseALU::FHE_XOR(const BinaryDigit &a, const BinaryDigit &b) {
    return BinaryDigit(
        cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::XOR, a.c, b.c));
}

BinaryDigit BaseALU::FHE_XNOR(const BinaryDigit &a, const BinaryDigit &b) {
    return BinaryDigit(
        cfhe_base->GetBinFHEContext().EvalBinGate(BINGATE::XNOR, a.c, b.c));
}

BinaryDigit BaseALU::FHE_NOT(const BinaryDigit &a) {
    return BinaryDigit(cfhe_base->GetBinFHEContext().EvalNOT(a.c));
}

BinaryDigit BaseALU::FHE_MUX(const BinaryDigit &s, const BinaryDigit &a,
                             const BinaryDigit &b) {
    return BinaryDigit(cfhe_base->GetBinFHEContext().EvalBinGate(
        CMUX, vector({a.c, b.c, s.c})));
}

BinaryDigit BaseALU::Constant0() {
    return BinaryDigit(FHE_False().c, 0, false);
}

BinaryDigit BaseALU::Constant1() { return BinaryDigit(FHE_True().c, 1, false); }

BinaryDigit BaseALU::Gate_AND(const BinaryDigit &a, const BinaryDigit &b) {
    if (a.is_ct && b.is_ct)
        return FHE_AND(a, b);
    if (a.is_ct && !b.is_ct)
        return b ? a : Constant0();
    if (!a.is_ct && b.is_ct)
        return a ? b : Constant0();
    return a & b;
}

BinaryDigit BaseALU::Gate_NAND(const BinaryDigit &a, const BinaryDigit &b) {
    if (a.is_ct && b.is_ct)
        return FHE_NAND(a, b);
    if (a.is_ct && !b.is_ct)
        return b ? Gate_NOT(a) : Constant1();
    if (!a.is_ct && b.is_ct)
        return a ? Gate_NOT(b) : Constant1();
    return !(a & b);
}

BinaryDigit BaseALU::Gate_OR(const BinaryDigit &a, const BinaryDigit &b) {
    if (a.is_ct && b.is_ct)
        return FHE_OR(a, b);
    if (a.is_ct && !b.is_ct)
        return b ? Constant1() : a;
    if (!a.is_ct && b.is_ct)
        return a ? Constant1() : b;
    return a | b;
}

BinaryDigit BaseALU::Gate_NOR(const BinaryDigit &a, const BinaryDigit &b) {
    if (a.is_ct && b.is_ct)
        return FHE_NOR(a, b);
    if (a.is_ct && !b.is_ct)
        return b ? Constant0() : Gate_NOT(a);
    if (!a.is_ct && b.is_ct)
        return a ? Constant0() : Gate_NOT(b);
    return !(a | b);
}

BinaryDigit BaseALU::Gate_XOR(const BinaryDigit &a, const BinaryDigit &b) {
    if (a.is_ct && b.is_ct)
        return FHE_XOR(a, b);
    if (a.is_ct && !b.is_ct)
        return b ? Gate_NOT(a) : a;
    if (!a.is_ct && b.is_ct)
        return a ? Gate_NOT(b) : b;
    return a ^ b;
}

BinaryDigit BaseALU::Gate_XNOR(const BinaryDigit &a, const BinaryDigit &b) {
    if (a.is_ct && b.is_ct)
        return FHE_XNOR(a, b);
    if (a.is_ct && !b.is_ct)
        return b ? a : Gate_NOT(a);
    if (!a.is_ct && b.is_ct)
        return a ? b : Gate_NOT(b);
    return !(a ^ b);
}

BinaryDigit BaseALU::Gate_NOT(const BinaryDigit &a) {
    if (a.is_ct)
        return FHE_NOT(a);
    return !a;
}

BinaryDigit BaseALU::Gate_MUX(const BinaryDigit &s, const BinaryDigit &a,
                              const BinaryDigit &b) {
    if (s.is_ct) {
        if (a.is_ct && b.is_ct) {
            return FHE_MUX(s, a, b);
        }
        if (a.is_ct && !b.is_ct) {
            return b.p ? Gate_OR(s, a) : Gate_AND(Gate_NOT(s), a);
        }
        if (!a.is_ct && b.is_ct) {
            return a.p ? Gate_OR(Gate_NOT(s), b) : Gate_AND(s, b);
        }
        return (a.p == b.p) ? a : (b.p ? s : Gate_NOT(s));
    }
    return s ? b : a;
}
