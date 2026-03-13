#include "CFHE_Eint.h"

ComputeFHE *CFHE_Eint::cfhe = nullptr;

CFHE_Eint::CFHE_Eint(int d, const ArithmeticsEngineType &ae_type) {
    if (cfhe == nullptr) {
        switch (ae_type) {
            case AE_OPTIMIZED: case AE_GATELOGIC:
                cfhe = new ComputeFHE(CCPARAM_STD128_3, ae_type);
                break;
            default:
                break;
        }
    }
    data = cfhe->EncryptInt(d);
}

bool CFHE_Eint::operator==(const CFHE_Eint &other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Eint::operator!=(const CFHE_Eint &other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpNotEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Eint::operator>(const CFHE_Eint& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpGT(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Eint::operator>=(const CFHE_Eint& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpGTEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Eint::operator<(const CFHE_Eint& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpLT(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Eint::operator<=(const CFHE_Eint& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpLTEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

CFHE_Eint CFHE_Eint::operator+(const CFHE_Eint &other) {
    CFHE_Eint tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Add(data, other.data);
    return tmp;
}

CFHE_Eint CFHE_Eint::operator+(uint other) {
    CFHE_Eint tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Add(data,cfhe->EncryptInt(other));
    return tmp;
}

CFHE_Eint CFHE_Eint::operator-(const CFHE_Eint &other) {
    CFHE_Eint tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Sub(data, other.data);
    return tmp;
}

CFHE_Eint CFHE_Eint::operator-(uint other) {
    CFHE_Eint tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Sub(data, cfhe->EncryptInt(other));
    return tmp;
}

CFHE_Eint CFHE_Eint::operator*(const CFHE_Eint &other) {
    CFHE_Eint tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Mul(data, other.data);
    return tmp;
}

CFHE_Eint CFHE_Eint::operator*(uint other) {
    CFHE_Eint tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Mul(data, cfhe->EncryptInt(other));
    return tmp;
}

CFHE_Eint CFHE_Eint::operator=(int n) {
    data = cfhe->EncryptInt(n);
    return *this;
}

CFHE_Eint CFHE_Eint::operator=(FixedPoint n) {
    this->data = n;
    return *this;
}

CFHE_Eint CFHE_Eint::operator-() {
    cout << "operator- called" << endl;
    CFHE_Eint tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Neg(data);
    return tmp;
}

uint CFHE_Eint::print() {
    return this->cfhe->DecryptInt(this->data);
}