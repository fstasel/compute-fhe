/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

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

BinaryDigit BaseALUSimulator::FHE_False() { return BinaryDigit(0); }

BinaryDigit BaseALUSimulator::FHE_True() { return BinaryDigit(1); }

BinaryDigit BaseALUSimulator::FHE_AND(const BinaryDigit &a,
                                      const BinaryDigit &b) {
    BinaryDigit out(a.p & b.p);
    out.is_ct = true;
    num_bs++;
    num_andor++;
    return out;
}

BinaryDigit BaseALUSimulator::FHE_NAND(const BinaryDigit &a,
                                       const BinaryDigit &b) {
    BinaryDigit out(!(a.p & b.p));
    out.is_ct = true;
    num_bs++;
    num_andor++;
    return out;
}

BinaryDigit BaseALUSimulator::FHE_OR(const BinaryDigit &a,
                                     const BinaryDigit &b) {
    BinaryDigit out(a.p | b.p);
    out.is_ct = true;
    num_bs++;
    num_andor++;
    return out;
}

BinaryDigit BaseALUSimulator::FHE_NOR(const BinaryDigit &a,
                                      const BinaryDigit &b) {
    BinaryDigit out(!(a.p | b.p));
    out.is_ct = true;
    num_bs++;
    num_andor++;
    return out;
}

BinaryDigit BaseALUSimulator::FHE_XOR(const BinaryDigit &a,
                                      const BinaryDigit &b) {
    BinaryDigit out(a.p ^ b.p);
    out.is_ct = true;
    num_bs++;
    num_xorxnor++;
    return out;
}

BinaryDigit BaseALUSimulator::FHE_XNOR(const BinaryDigit &a,
                                       const BinaryDigit &b) {
    BinaryDigit out(!(a.p ^ b.p));
    out.is_ct = true;
    num_bs++;
    num_xorxnor++;
    return out;
}

BinaryDigit BaseALUSimulator::FHE_NOT(const BinaryDigit &a) {
    BinaryDigit out(!a.p);
    out.is_ct = true;
    num_not++;
    return out;
}

BinaryDigit BaseALUSimulator::FHE_MUX(const BinaryDigit &s,
                                      const BinaryDigit &a,
                                      const BinaryDigit &b) {
    BinaryDigit out(s.p ? b.p : a.p);
    out.is_ct = true;
    num_bs += 3;
    num_andor += 3;
    return out;
}
