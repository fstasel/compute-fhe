#include <computefhe/CFHE_Integer.h>
using namespace computefhe;

ComputeFHE *CFHE_Integer::cfhe = nullptr;

CFHE_Integer::CFHE_Integer(int d, size_t s, const ArithmeticsEngineType &ae_type) {
    if (cfhe == nullptr) {
        switch (ae_type) {
            case AE_OPTIMIZED: case AE_GATELOGIC:
                cfhe = new ComputeFHE(CCPARAM_TOY, ae_type);
                break;
            default:
                break;
        }
    }
    size = s;
    data = cfhe->EncryptInt(d, size);
}

bool CFHE_Integer::operator==(const CFHE_Integer &other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator!=(const CFHE_Integer &other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpNotEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator>(const CFHE_Integer& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpGT(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator>=(const CFHE_Integer& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpGTEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator<(const CFHE_Integer& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpLT(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator<=(const CFHE_Integer& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpLTEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

CFHE_Integer CFHE_Integer::operator+(const CFHE_Integer &other) {
    CFHE_Integer tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->AddNC(data, other.data);
    return tmp;
}

CFHE_Integer CFHE_Integer::operator+(uint other) {
    CFHE_Integer tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->AddNC(data,cfhe->EncryptInt(other, size));
    return tmp;
}

CFHE_Integer CFHE_Integer::operator-(const CFHE_Integer &other) {
    CFHE_Integer tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->SubNC(data, other.data);
    return tmp;
}

CFHE_Integer CFHE_Integer::operator-(uint other) {
    CFHE_Integer tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->SubNC(data, cfhe->EncryptInt(other, size));
    return tmp;
}

CFHE_Integer CFHE_Integer::operator*(const CFHE_Integer &other) {
    CFHE_Integer tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Mul(data, other.data);
    return tmp;
}

CFHE_Integer CFHE_Integer::operator*(uint other) {
    CFHE_Integer tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Mul(data, cfhe->EncryptInt(other, size));
    return tmp;
}

CFHE_Integer CFHE_Integer::operator=(int n) {
    data = cfhe->EncryptInt(n, size);
    return *this;
}

CFHE_Integer CFHE_Integer::operator=(FixedPoint n) {
    this->data = n;
    return *this;
}

CFHE_Integer CFHE_Integer::operator-() {
    CFHE_Integer tmp;
    tmp.data = cfhe->GetArithmeticsEngine()->Neg(data);
    return tmp;
}

ostream& computefhe::operator<<(ostream &out, const CFHE_Integer& obj) {
    out << obj.cfhe->DecryptInt(obj.data, obj.size);
    return out;
}