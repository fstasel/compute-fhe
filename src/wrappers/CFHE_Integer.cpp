#include <computefhe/CFHE_Integer.h>
using namespace computefhe;

ComputeFHE *CFHE_Integer::cfhe = nullptr;

CFHE_Integer::CFHE_Integer() {
    if (cfhe == nullptr)
        Init();
    data = FixedPoint();
    size = 0;
}

CFHE_Integer::CFHE_Integer(uint d, size_t s) {
    if (cfhe == nullptr)
        Init();
    data = cfhe->GetConstantInt(d, s);
    size = s;
}

CFHE_Integer::~CFHE_Integer() {
    // empty
}

void CFHE_Integer::Init(CryptoContextParam cc_param, ArithmeticsEngineType ae_type) {
    if (cfhe != nullptr)
        delete cfhe;
    cfhe = new ComputeFHE(cc_param, ae_type);
}

bool CFHE_Integer::operator==(const CFHE_Integer& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator!=(const CFHE_Integer &other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpNotEq(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator>(const CFHE_Integer& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpGT_U(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator>=(const CFHE_Integer& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpGTEq_U(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator<(const CFHE_Integer& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpLT_U(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

bool CFHE_Integer::operator<=(const CFHE_Integer& other) {
    auto res = cfhe->GetArithmeticsEngine()->CmpLTEq_U(data, other.data);
    return cfhe->DecryptBool(res) ? true : false;
}

CFHE_Integer CFHE_Integer::operator+(const CFHE_Integer &other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe->GetArithmeticsEngine()->AddNC(data, other.data);
    return tmp;
}

CFHE_Integer CFHE_Integer::operator+(uint other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe->GetArithmeticsEngine()->AddNC(data,cfhe->GetConstantInt(other, size));
    return tmp;
}

CFHE_Integer CFHE_Integer::operator-(const CFHE_Integer &other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe->GetArithmeticsEngine()->SubNC(data, other.data);
    return tmp;
}

CFHE_Integer CFHE_Integer::operator-(uint other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe->GetArithmeticsEngine()->SubNC(data, cfhe->GetConstantInt(other, size));
    return tmp;
}

CFHE_Integer CFHE_Integer::operator*(const CFHE_Integer &other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe->GetArithmeticsEngine()->Mul(data, other.data);
    return tmp;
}

CFHE_Integer CFHE_Integer::operator*(uint other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe->GetArithmeticsEngine()->Mul(data, cfhe->GetConstantInt(other, size));
    return tmp;
}

CFHE_Integer& CFHE_Integer::operator=(uint n) {
    data = cfhe->GetConstantInt(n, size);
    return *this;
}

CFHE_Integer& CFHE_Integer::operator=(FixedPoint n) {
    this->data = n;
    return *this;
}

CFHE_Integer CFHE_Integer::operator-() {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe->GetArithmeticsEngine()->Neg(data);
    return tmp;
}

ostream& computefhe::operator<<(ostream &out, const CFHE_Integer& obj) {
    out << obj.cfhe->DecryptInt(obj.data, obj.size);
    return out;
}