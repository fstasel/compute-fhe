
#include <computefhe/ComputeFHE.h>
#include <computefhe/AEGateLogic.h>
#include <computefhe/AEOptimized.h>

#include <iostream>
#include <computefhe/ComputeFHE.h>
using namespace computefhe;

void ComputeFHE::createCC()
{
    switch (cc_param)
    {
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

void ComputeFHE::generateKeys()
{
    sk = cc.KeyGen();
    cc.BTKeyGen(sk);
}

double ComputeFHE::extractNoise(ConstLWECiphertext &ct)
{
    // OpenFHE Decryption routine
    const auto &mod = ct->GetModulus();
    const auto &a = ct->GetA();
    auto s = sk->GetElement();
    uint32_t n = s.GetLength();
    auto mu = mod.ComputeMu();
    s.SwitchModulus(mod);
    NativeInteger inner(0);
    for (size_t i = 0; i < n; ++i)
    {
        inner += a[i].ModMulFast(s[i], mod, mu);
    }
    inner.ModEq(mod);
    NativeInteger r = ct->GetB();
    r.ModSubFastEq(inner, mod);
    LWEPlaintextModulus p = 4;
    r.ModAddFastEq((mod / (p * 2)), mod);
    LWEPlaintext result = ((NativeInteger(p) * r) / mod).ConvertToInt();
    double error =
        (static_cast<double>(p) * (r.ConvertToDouble() - mod.ConvertToDouble() / (p * 2))) / mod.ConvertToDouble() -
        static_cast<double>(result);
    return error * mod.ConvertToDouble() / static_cast<double>(p);
}

void ComputeFHE::createAE()
{
    switch (ae_type)
    {
    case AE_OPTIMIZED:
        ae = new AEOptimized(this);
        break;

    case AE_GATELOGIC:
    default:
        ae = new AEGateLogic(this);
    }
}

ComputeFHE::ComputeFHE() : ComputeFHE(CCPARAM_STD128, AE_GATELOGIC)
{
}

ComputeFHE::ComputeFHE(CryptoContextParam param) : ComputeFHE(param, AE_GATELOGIC)
{
}

ComputeFHE::ComputeFHE(ArithmeticsEngineType engine_type) : ComputeFHE(CCPARAM_STD128, engine_type)
{
}

ComputeFHE::~ComputeFHE()
{
    delete ae;
}

ComputeFHE::ComputeFHE(CryptoContextParam param, ArithmeticsEngineType engine_type)
    : cc_param(param), ae_type(engine_type)
{
    createCC();
    generateKeys();
    createAE();
}

BinFHEContext &ComputeFHE::GetBinFHEContext()
{
    return cc;
}

BaseArithmeticsEngine *ComputeFHE::GetArithmeticsEngine()
{
    return ae;
}

CryptoContextParam ComputeFHE::GetCryptoContextParam()
{
    return cc_param;
}

ArithmeticsEngineType ComputeFHE::GetArithmeticsEngineType()
{
    return ae_type;
}

const LWEPrivateKey &ComputeFHE::GetLWEPrivateKey()
{
    return sk;
}

FixedPoint ComputeFHE::EncryptInt(uint64_t pt, size_t n_digits, bool fresh)
{
    FixedPoint out(n_digits);
    for (size_t i = 0; i < n_digits; i++)
    {
        out[i] = cc.Encrypt(sk, pt % 2, FRESH);
        pt /= 2;
        if (!fresh)
        {
            out[i] = cc.Bootstrap(out[i]);
        }
    }
    return out;
}

uint64_t ComputeFHE::DecryptInt(const FixedPoint &ct, size_t n_digits)
{
    uint64_t out = 0;
    LWEPlaintext result;
    n_digits = (n_digits == 0) ? ct.size() : n_digits;
    for (size_t i = 0; i < n_digits; i++)
    {
        cc.Decrypt(sk, ct[i], &result);
        out += result * (1UL << i);
    }
    return out;
}

LWECiphertext ComputeFHE::EncryptBool(bool pt, bool fresh)
{
    LWECiphertext out = cc.Encrypt(sk, pt == 0 ? 0 : 1, FRESH);
    if (!fresh)
    {
        out = cc.Bootstrap(out);
    }
    return out;
}

bool ComputeFHE::DecryptBool(ConstLWECiphertext &ct)
{
    LWEPlaintext result;
    cc.Decrypt(sk, ct, &result);
    return (bool)result;
}

FixedPoint computefhe::ComputeFHE::GetConstantInt(uint64_t pt, size_t n_digits)
{
    FixedPoint out(n_digits);
    for (size_t i = 0; i < n_digits; i++)
    {
        out[i] = (pt % 2) ? ae->GetConstantTrue() : ae->GetConstantFalse();
        pt /= 2;
    }
    return out;
}

void ComputeFHE::PrintCryptoContextParams()
{
    cout << "cc Q=" << cc.GetParams()->GetLWEParams()->GetQ() << endl
         << "cc q=" << cc.GetParams()->GetLWEParams()->Getq() << endl
         << "cc N=" << cc.GetParams()->GetLWEParams()->GetN() << endl
         << "cc n=" << cc.GetParams()->GetLWEParams()->Getn() << endl
         << "cc BaseKS=" << cc.GetParams()->GetLWEParams()->GetBaseKS() << endl
         << "cc beta=" << cc.GetBeta() << endl
         << "cc max pt space=" << cc.GetMaxPlaintextSpace() << endl;
}

void ComputeFHE::PrintLWECiphertextParams(ConstLWECiphertext &ct)
{
    cout << "ct len=" << ct->GetLength() << endl
         << "ct mod=" << ct->GetModulus() << endl
         << "ct pt mod=" << ct->GetptModulus() << endl
         << "ct a=" << ct->GetA() << endl
         << "ct b=" << ct->GetB() << endl;
}