#include <computefhe/SimOptimized.h>
using namespace computefhe;

SimOptimized::SimOptimized(ComputeFHE *cfhe)
    : BaseALU(cfhe), BaseALUSimulator(cfhe), ALUGateLogic(cfhe),
      SimGateLogic(cfhe), ALUOptimized(cfhe) {}

BinaryDigit SimOptimized::FHE_MAJ(const BinaryDigit &a, const BinaryDigit &b,
                                  const BinaryDigit &c) {
    BinaryDigit out(a.p + b.p + c.p >= 2);
    out.is_ct = true;
    num_bs++;
    num_maj++;
    return out;
}

BinaryDigit SimOptimized::FHE_XOR3(const BinaryDigit &a, const BinaryDigit &b,
                                   const BinaryDigit &c) {
    BinaryDigit out(a.p ^ b.p ^ c.p);
    out.is_ct = true;
    num_bs++;
    num_xor3++;
    return out;
}

BinaryDigit SimOptimized::FHE_MulAdd(const BinaryDigit &m, const BinaryDigit &a,
                                     const BinaryDigit &b,
                                     BinaryDigit *carry_out) {
    BinaryDigit out((m.p & a.p) ^ b.p);
    out.is_ct = true;
    if (carry_out) {
        *carry_out = BinaryDigit(m.p & a.p & b.p);
        num_bs += 2;
        num_mac++;
    } else {
        num_bs++;
        num_ma++;
    }
    return out;
}

BinaryDigit SimOptimized::FHE_MUX(const BinaryDigit &s, const BinaryDigit &a,
                                  const BinaryDigit &b) {
    BinaryDigit out(s.p ? b.p : a.p);
    out.is_ct = true;
    num_bs += 2;
    num_mux++;
    return out;
}
