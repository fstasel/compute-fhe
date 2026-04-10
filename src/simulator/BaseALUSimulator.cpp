#include <computefhe/BaseALUSimulator.h>
#include <iostream>

using namespace std;
using namespace computefhe;

BaseALUSimulator::BaseALUSimulator(ComputeFHE *cfhe) : BaseALU(cfhe) {
    ResetStats();
}

void BaseALUSimulator::PrintStats() {
    cout << "--- Stats: ---" << endl;
    cout << "BS: " << num_bs << endl;
    cout << "NOT: " << num_not << endl;
    cout << "AND/OR: " << num_andor << endl;
    cout << "XOR/XNOR: " << num_xorxnor << endl;
    cout << "*XOR3: " << num_xor3 << endl;
    cout << "*MAJ: " << num_maj << endl;
    cout << "*MA: " << num_ma << endl;
    cout << "*MAC: " << num_mac << endl;
    cout << "*DS: " << num_ds << endl;
    cout << "*MUX: " << num_mux << endl;
    cout << "--------------" << endl;
}

void BaseALUSimulator::ResetStats() {
    num_bs = 0;
    num_not = 0;
    num_andor = 0;
    num_xorxnor = 0;
    num_xor3 = 0;
    num_maj = 0;
    num_ma = 0;
    num_mac = 0;
    num_ds = 0;
    num_mux = 0;
}

uint BaseALUSimulator::GetNumBS() { return num_bs; }

BinaryDigit BaseALUSimulator::GetConstantFalse() { return BinaryDigit(0); }

BinaryDigit BaseALUSimulator::GetConstantTrue() { return BinaryDigit(1); }

BinaryDigit BaseALUSimulator::Gate_AND(const BinaryDigit &a,
                                       const BinaryDigit &b) {
    num_bs++;
    num_andor++;
    return BinaryDigit(a.p & b.p);
}

BinaryDigit BaseALUSimulator::Gate_NAND(const BinaryDigit &a,
                                        const BinaryDigit &b) {
    num_bs++;
    num_andor++;
    return BinaryDigit(!(a.p & b.p));
}

BinaryDigit BaseALUSimulator::Gate_OR(const BinaryDigit &a,
                                      const BinaryDigit &b) {
    num_bs++;
    num_andor++;
    return BinaryDigit(a.p | b.p);
}

BinaryDigit BaseALUSimulator::Gate_NOR(const BinaryDigit &a,
                                       const BinaryDigit &b) {
    num_bs++;
    num_andor++;
    return BinaryDigit(!(a.p | b.p));
}

BinaryDigit BaseALUSimulator::Gate_XOR(const BinaryDigit &a,
                                       const BinaryDigit &b) {
    num_bs++;
    num_xorxnor++;
    return BinaryDigit(a.p ^ b.p);
}

BinaryDigit BaseALUSimulator::Gate_XNOR(const BinaryDigit &a,
                                        const BinaryDigit &b) {
    num_bs++;
    num_xorxnor++;
    return BinaryDigit(!(a.p ^ b.p));
}

BinaryDigit BaseALUSimulator::Gate_NOT(const BinaryDigit &a) {
    num_not++;
    return BinaryDigit(!a.p);
}
FixedPoint BaseALUSimulator::ToggleMSB(const FixedPoint &a) {
    num_not++;
    FixedPoint t = a;
    t.back() = BinaryDigit(!t.back().p);
    return t;
}
