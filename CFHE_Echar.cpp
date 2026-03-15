#include "CFHE_Echar.h"

ComputeFHE *CFHE_Echar::cfhe = nullptr;

CFHE_Echar::CFHE_Echar(char d, const ArithmeticsEngineType &ae_type) {
    if (cfhe == nullptr) {
        switch (ae_type) {
            case AE_OPTIMIZED: case AE_GATELOGIC:
                cfhe = new ComputeFHE(CCPARAM_STD128_3, ae_type);
                break;
            default:
                break;
        }
    }
    data = cfhe->EncryptInt(d, sizeof(char) * 8);
}

bool CFHE_Echar::operator==(const CFHE_Echar &other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpEq(data, other.data);
    return cfhe->DecryptBool(res);
}

bool CFHE_Echar::operator!=(const CFHE_Echar &other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpNotEq(data, other.data);
    return cfhe->DecryptBool(res);
}

bool CFHE_Echar::operator>(const CFHE_Echar& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpGT(data, other.data);
    return cfhe->DecryptBool(res);
}

bool CFHE_Echar::operator>=(const CFHE_Echar& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpGTEq(data, other.data);
    return cfhe->DecryptBool(res);
}

bool CFHE_Echar::operator<(const CFHE_Echar& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpLT(data, other.data);
    return cfhe->DecryptBool(res);
}

bool CFHE_Echar::operator<=(const CFHE_Echar& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpLTEq(data, other.data);
    return cfhe->DecryptBool(res);
}

CFHE_Echar CFHE_Echar::operator+(const CFHE_Echar &other) {
    CFHE_Echar tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Add(data, other.data);
    return tmp;
}

CFHE_Echar CFHE_Echar::operator+(uint other) {
    CFHE_Echar tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Add(data,cfhe->EncryptInt(other, sizeof(char) * 8));
    return tmp;
}

CFHE_Echar CFHE_Echar::operator-(const CFHE_Echar &other) {
    CFHE_Echar tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Sub(data, other.data);
    return tmp;
}

CFHE_Echar CFHE_Echar::operator-(uint other) {
    CFHE_Echar tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Sub(data, cfhe->EncryptInt(other, sizeof(char) * 8));
    return tmp;
}

CFHE_Echar CFHE_Echar::operator*(const CFHE_Echar &other) {
    CFHE_Echar tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Mul(data, other.data);
    return tmp;
}

CFHE_Echar CFHE_Echar::operator*(uint other) {
    CFHE_Echar tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Mul(data, cfhe->EncryptInt(other, sizeof(char) * 8));
    return tmp;
}

CFHE_Echar CFHE_Echar::operator=(char n) {
    data = cfhe->EncryptInt(n, sizeof(char) * 8);
    return *this;
}

CFHE_Echar CFHE_Echar::operator=(FixedPoint n) {
    this->data = n;
    return *this;
}

CFHE_Echar CFHE_Echar::operator-() {
    CFHE_Echar tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Neg(data);
    return tmp;
}

char CFHE_Echar::print() {
    return static_cast<char>(this->cfhe->DecryptInt(this->data));
}