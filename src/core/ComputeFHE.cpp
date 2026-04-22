#include <computefhe/ComputeFHE.h>

#include <iostream>
using namespace computefhe;

namespace computefhe {
    ComputeFHE *cfhe_base = nullptr;
    bool CLIENT_MODE = false;
} // namespace computefhe

void computefhe::Init(CryptoContextParam cc_param, ALUType alu_type,
                      bool client_mode, bool simulation_mode) {
    if (cfhe_base != nullptr)
        delete cfhe_base;
    cfhe_base = new ComputeFHE(cc_param, alu_type, simulation_mode);
    CLIENT_MODE = client_mode;
}

void computefhe::Finalize() {
    if (cfhe_base != nullptr)
        delete cfhe_base;
    cfhe_base = nullptr;
}

void ComputeFHE::createCC() {
    switch (cc_param) {
    case CCPARAM_STD256_LMKCDEY:
        cc.GenerateBinFHEContext(STD256_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD256_3_LMKCDEY:
        cc.GenerateBinFHEContext(STD256_3_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD256:
        cc.GenerateBinFHEContext(STD256);
        break;

    case CCPARAM_STD256_3:
        cc.GenerateBinFHEContext(STD256_3);
        break;

    case CCPARAM_STD192_LMKCDEY:
        cc.GenerateBinFHEContext(STD192_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD192_3_LMKCDEY:
        cc.GenerateBinFHEContext(STD192_3_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD192:
        cc.GenerateBinFHEContext(STD192);
        break;

    case CCPARAM_STD192_3:
        cc.GenerateBinFHEContext(STD192_3);
        break;

    case CCPARAM_STD128_LMKCDEY:
        cc.GenerateBinFHEContext(STD128_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD128_3_LMKCDEY:
        cc.GenerateBinFHEContext(STD128_3_LMKCDEY, LMKCDEY);
        break;

    case CCPARAM_STD128:
        cc.GenerateBinFHEContext(STD128);
        break;

    case CCPARAM_STD128_3:
        cc.GenerateBinFHEContext(STD128_3);
        break;

    case CCPARAM_TOY:
    default:
        cc.GenerateBinFHEContext(TOY);
    }
}

void ComputeFHE::generateKeys() {
    sk = cc.KeyGen();
    cc.BTKeyGen(sk);
}

double ComputeFHE::extractNoise(ConstLWECiphertext &ct) {
    // OpenFHE Decryption routine
    const auto &mod = ct->GetModulus();
    const auto &a = ct->GetA();
    auto s = sk->GetElement();
    uint32_t n = s.GetLength();
    auto mu = mod.ComputeMu();
    s.SwitchModulus(mod);
    NativeInteger inner(0);
    for (size_t i = 0; i < n; ++i) {
        inner += a[i].ModMulFast(s[i], mod, mu);
    }
    inner.ModEq(mod);
    NativeInteger r = ct->GetB();
    r.ModSubFastEq(inner, mod);
    LWEPlaintextModulus p = 4;
    r.ModAddFastEq((mod / (p * 2)), mod);
    LWEPlaintext result = ((NativeInteger(p) * r) / mod).ConvertToInt();
    double error = (static_cast<double>(p) *
                    (r.ConvertToDouble() - mod.ConvertToDouble() / (p * 2))) /
                       mod.ConvertToDouble() -
                   static_cast<double>(result);
    return error * mod.ConvertToDouble() / static_cast<double>(p);
}

void ComputeFHE::createALU() {
    switch (alu_type) {
    case ALU_OPTIMIZED:
        if (sim_mode) {
            alu = new SimOptimized(this);
        } else {
            alu = new ALUOptimized(this);
        }
        break;
    case ALU_GATELOGIC:
    default:
        if (sim_mode) {
            alu = new SimGateLogic(this);
        } else {
            alu = new ALUGateLogic(this);
        }
        break;
    }
}

ComputeFHE::ComputeFHE(bool simulation_mode)
    : ComputeFHE(CCPARAM_STD128, ALU_GATELOGIC, simulation_mode) {}

ComputeFHE::ComputeFHE(CryptoContextParam param, bool simulation_mode)
    : ComputeFHE(param, ALU_GATELOGIC, simulation_mode) {}

ComputeFHE::ComputeFHE(ALUType alu_type, bool simulation_mode)
    : ComputeFHE(CCPARAM_STD128, alu_type, simulation_mode) {}

ComputeFHE::~ComputeFHE() { delete alu; }

ComputeFHE::ComputeFHE(CryptoContextParam param, ALUType alu_type,
                       bool simulation_mode)
    : cc_param(param), alu_type(alu_type), sim_mode(simulation_mode) {
    createCC();
    generateKeys();
    createALU();
}

BinFHEContext &ComputeFHE::GetBinFHEContext() { return cc; }

BaseALU *ComputeFHE::GetALU() { return alu; }

BaseALUSimulator *ComputeFHE::GetSimulator() {
    if (sim_mode)
        return dynamic_cast<BaseALUSimulator *>(alu);
    return nullptr;
}

CryptoContextParam ComputeFHE::GetCryptoContextParam() { return cc_param; }

ALUType ComputeFHE::GetALUType() { return alu_type; }

const LWEPrivateKey &ComputeFHE::GetLWEPrivateKey() { return sk; }

FixedPoint ComputeFHE::EncryptInt(uint64_t pt, size_t n_digits, bool fresh) {
    FixedPoint out(n_digits);
    for (size_t i = 0; i < n_digits; i++) {
        if (sim_mode) {
            out[i] = pt % 2;
            out[i].is_ct = true;
        } else {
            out[i] = cc.Encrypt(sk, pt % 2, FRESH);
        }
        pt /= 2;
        if (!fresh && !sim_mode) {
            out[i] = cc.Bootstrap(out[i]);
        }
    }
    return out;
}

uint64_t ComputeFHE::DecryptInt(const FixedPoint &ct, size_t n_digits) {
    uint64_t out = 0;
    LWEPlaintext result;
    n_digits = (n_digits == 0) ? ct.size() : n_digits;
    for (size_t i = 0; i < n_digits; i++) {
        if (sim_mode) {
            result = ct[i];
        } else {
            if (ct[i].is_ct)
                cc.Decrypt(sk, ct[i], &result);
            else
                result = ct[i];
        }
        out += result * (1UL << i);
    }
    return out;
}

BinaryDigit ComputeFHE::EncryptBool(bool pt, bool fresh) {
    if (sim_mode) {
        BinaryDigit out(pt);
        out.is_ct = true;
        return out;
    }
    LWECiphertext out = cc.Encrypt(sk, pt == 0 ? 0 : 1, FRESH);
    if (!fresh) {
        out = cc.Bootstrap(out);
    }
    return BinaryDigit(out);
}

bool ComputeFHE::DecryptBool(const BinaryDigit &ct) {
    if (sim_mode) {
        return ct.p;
    }
    LWEPlaintext result;
    cc.Decrypt(sk, ct, &result);
    return (bool)result;
}

FixedPoint computefhe::ComputeFHE::GetConstantInt(uint64_t pt,
                                                  size_t n_digits) {
    FixedPoint out(n_digits);
    for (size_t i = 0; i < n_digits; i++) {
        out[i] = (pt % 2) ? alu->Constant1() : alu->Constant0();
        pt /= 2;
    }
    return out;
}

void ComputeFHE::PrintCryptoContextParams() {
    cout << "cc Q=" << cc.GetParams()->GetLWEParams()->GetQ() << endl
         << "cc q=" << cc.GetParams()->GetLWEParams()->Getq() << endl
         << "cc N=" << cc.GetParams()->GetLWEParams()->GetN() << endl
         << "cc n=" << cc.GetParams()->GetLWEParams()->Getn() << endl
         << "cc BaseKS=" << cc.GetParams()->GetLWEParams()->GetBaseKS() << endl
         << "cc beta=" << cc.GetBeta() << endl
         << "cc max pt space=" << cc.GetMaxPlaintextSpace() << endl;
}

void ComputeFHE::PrintLWECiphertextParams(ConstLWECiphertext &ct) {
    cout << "ct len=" << ct->GetLength() << endl
         << "ct mod=" << ct->GetModulus() << endl
         << "ct pt mod=" << ct->GetptModulus() << endl
         << "ct a=" << ct->GetA() << endl
         << "ct b=" << ct->GetB() << endl;
}