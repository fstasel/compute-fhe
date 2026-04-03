#include <computefhe/CFHE_Integer.h>
#include <computefhe/ConditionManager.h>

using namespace computefhe;

namespace computefhe {
    ComputeFHE *cfhe_base = nullptr;
    bool CLIENT_MODE = false;
} // namespace computefhe

void computefhe::Init(CryptoContextParam cc_param,
                      ArithmeticsEngineType ae_type, bool client_mode) {
    if (cfhe_base != nullptr)
        delete cfhe_base;
    cfhe_base = new ComputeFHE(cc_param, ae_type);
    CLIENT_MODE = client_mode;
}

void computefhe::Finalize() {
    if (cfhe_base != nullptr)
        delete cfhe_base;
    cfhe_base = nullptr;
}

int64_t CFHE_Integer::sign_extend(uint64_t d, size_t n_digits) {
    if (n_digits == 0 || n_digits >= 64)
        return (int64_t)d;
    uint64_t mask = 1ULL << (n_digits - 1);
    return (int64_t)((d ^ mask) - mask);
}

void CFHE_Integer::_sync_var() {
    if (ConditionManager::conditional_mode()) {
        ConditionManager::register_variable((void *)this, &data);
    }
}

void CFHE_Integer::_desync_var() {
    if (ConditionManager::conditional_mode()) {
        ConditionManager::unregister_variable((void *)this);
    }
}

bool CFHE_Integer::promote(const CFHE_Integer &a, const CFHE_Integer &b,
                           FixedPoint &a_out, FixedPoint &b_out) {
    if (a.size == b.size) {
        a_out = a.data;
        b_out = b.data;
        return a.sign && b.sign;
    }

    size_t n = (a.size > b.size) ? a.size : b.size;
    bool s = (a.size > b.size) ? a.sign : b.sign;
    a_out.resize(n);
    b_out.resize(n);

    LWECiphertext last_a = a.data.back();
    LWECiphertext last_b = b.data.back();

    for (size_t i = 0; i < n; i++) {
        if (i < a.size)
            a_out[i] = a.data[i];
        else if (a.sign)
            a_out[i] = last_a;
        else
            a_out[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();

        if (i < b.size)
            b_out[i] = b.data[i];
        else if (b.sign)
            b_out[i] = last_b;
        else
            b_out[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    return s;
}

FixedPoint CFHE_Integer::promote(const CFHE_Integer &a, size_t s) {
    if (a.size == s) {
        return FixedPoint(a.data);
    }
    FixedPoint out(s);
    LWECiphertext last = a.data.back();
    for (size_t i = 0; i < s; i++) {
        if (i < a.size)
            out[i] = a.data[i];
        else if (a.sign)
            out[i] = last;
        else
            out[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    return out;
}

CFHE_Integer::CFHE_Integer(size_t n_digits, bool is_signed) {
    if (cfhe_base == nullptr)
        Init();
    data = cfhe_base->GetConstantInt(0, n_digits);
    size = n_digits;
    sign = is_signed;
}

CFHE_Integer::CFHE_Integer(int64_t d, size_t n_digits) {
    if (cfhe_base == nullptr)
        Init();
    data = cfhe_base->GetConstantInt((uint64_t)d, n_digits);
    size = n_digits;
    sign = true;
}

CFHE_Integer::CFHE_Integer(uint64_t d, size_t n_digits) {
    if (cfhe_base == nullptr)
        Init();
    data = cfhe_base->GetConstantInt(d, n_digits);
    size = n_digits;
    sign = false;
}

CFHE_Integer::CFHE_Integer(const FixedPoint &fp, bool is_signed) {
    if (cfhe_base == nullptr)
        Init();
    data = fp;
    size = fp.size();
    sign = is_signed;
}

CFHE_Integer::CFHE_Integer(const CFHE_Integer &other) {
    if (cfhe_base == nullptr)
        Init();
    data.resize(other.size);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = COPY_CT(other.data[i]);
    }
    size = other.size;
    sign = other.sign;
}

CFHE_Integer::~CFHE_Integer() { _desync_var(); }

const FixedPoint &CFHE_Integer::getData() const { return data; }

size_t CFHE_Integer::getSize() const { return size; }

bool CFHE_Integer::isSigned() const { return sign; }

const CFHE_Integer CFHE_Integer::operator==(const CFHE_Integer &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp({cfhe_base->GetArithmeticsEngine()->CmpEq(a, b)});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator!=(const CFHE_Integer &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp({cfhe_base->GetArithmeticsEngine()->CmpNotEq(a, b)});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator>(const CFHE_Integer &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp({(sign && other.sign)
                       ? cfhe_base->GetArithmeticsEngine()->CmpGT(a, b)
                       : cfhe_base->GetArithmeticsEngine()->CmpGT_U(a, b)});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator>=(const CFHE_Integer &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp({(sign && other.sign)
                       ? cfhe_base->GetArithmeticsEngine()->CmpGTEq(a, b)
                       : cfhe_base->GetArithmeticsEngine()->CmpGTEq_U(a, b)});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator<(const CFHE_Integer &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp({(sign && other.sign)
                       ? cfhe_base->GetArithmeticsEngine()->CmpLT(a, b)
                       : cfhe_base->GetArithmeticsEngine()->CmpLT_U(a, b)});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator<=(const CFHE_Integer &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp({(sign && other.sign)
                       ? cfhe_base->GetArithmeticsEngine()->CmpLTEq(a, b)
                       : cfhe_base->GetArithmeticsEngine()->CmpLTEq_U(a, b)});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator==(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp({cfhe_base->GetArithmeticsEngine()->CmpEq(
        data, cfhe_base->GetConstantInt(other, size))});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator!=(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp({cfhe_base->GetArithmeticsEngine()->CmpNotEq(
        data, cfhe_base->GetConstantInt(other, size))});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator>(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp({sign ? cfhe_base->GetArithmeticsEngine()->CmpGT(
                              data, cfhe_base->GetConstantInt(other, size))
                        : cfhe_base->GetArithmeticsEngine()->CmpGT_U(
                              data, cfhe_base->GetConstantInt(other, size))});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator>=(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp({sign ? cfhe_base->GetArithmeticsEngine()->CmpGTEq(
                              data, cfhe_base->GetConstantInt(other, size))
                        : cfhe_base->GetArithmeticsEngine()->CmpGTEq_U(
                              data, cfhe_base->GetConstantInt(other, size))});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator<(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp({sign ? cfhe_base->GetArithmeticsEngine()->CmpLT(
                              data, cfhe_base->GetConstantInt(other, size))
                        : cfhe_base->GetArithmeticsEngine()->CmpLT_U(
                              data, cfhe_base->GetConstantInt(other, size))});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator<=(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp({sign ? cfhe_base->GetArithmeticsEngine()->CmpLTEq(
                              data, cfhe_base->GetConstantInt(other, size))
                        : cfhe_base->GetArithmeticsEngine()->CmpLTEq_U(
                              data, cfhe_base->GetConstantInt(other, size))});
    return CFHE_Integer(fp, false);
}

const CFHE_Integer CFHE_Integer::operator+(const CFHE_Integer &other) const {
    FixedPoint a, b;
    bool s = promote(*this, other, a, b);
    FixedPoint fp(cfhe_base->GetArithmeticsEngine()->AddNC(a, b));
    return CFHE_Integer(fp, s);
}

const CFHE_Integer CFHE_Integer::operator+=(const CFHE_Integer &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    data = cfhe_base->GetArithmeticsEngine()->AddNC(data, o);
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator-(const CFHE_Integer &other) const {
    FixedPoint a, b;
    bool s = promote(*this, other, a, b);
    FixedPoint fp(cfhe_base->GetArithmeticsEngine()->SubNC(a, b));
    return CFHE_Integer(fp, s);
}

const CFHE_Integer CFHE_Integer::operator-=(const CFHE_Integer &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    data = cfhe_base->GetArithmeticsEngine()->SubNC(data, o);
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator*(const CFHE_Integer &other) const {
    FixedPoint a, b;
    bool s = promote(*this, other, a, b);
    FixedPoint fp(cfhe_base->GetArithmeticsEngine()->Mul(a, b));
    return CFHE_Integer(fp, s);
}

const CFHE_Integer CFHE_Integer::operator*=(const CFHE_Integer &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    data = cfhe_base->GetArithmeticsEngine()->Mul(data, o);
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator+(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this + CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign);
}

const CFHE_Integer CFHE_Integer::operator+=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this += CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign);
}

const CFHE_Integer CFHE_Integer::operator-(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this - CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign);
}

const CFHE_Integer CFHE_Integer::operator-=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this -= CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign);
}

const CFHE_Integer CFHE_Integer::operator*(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this * CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign);
}

const CFHE_Integer CFHE_Integer::operator*=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this *= CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign);
}

const CFHE_Integer CFHE_Integer::operator-() const {
    return CFHE_Integer(cfhe_base->GetArithmeticsEngine()->Neg(data), sign);
}

const CFHE_Integer CFHE_Integer::operator&(const CFHE_Integer &other) const {
    FixedPoint o = promote(other, size);
    FixedPoint fp(size);
    for (size_t i = 0; i < size; i++) {
        fp[i] = cfhe_base->GetArithmeticsEngine()->Gate_AND(data[i], o[i]);
    }
    return CFHE_Integer(fp, sign);
}

const CFHE_Integer CFHE_Integer::operator&=(const CFHE_Integer &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    for (size_t i = 0; i < size; i++) {
        data[i] = cfhe_base->GetArithmeticsEngine()->Gate_AND(data[i], o[i]);
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator&(uint64_t other) const {
    CFHE_Integer r(size, sign);
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            r.data[i] = COPY_CT(data[i]);
        else
            r.data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    return r;
}

const CFHE_Integer CFHE_Integer::operator&=(uint64_t other) {
    _sync_var();
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (!bit)
            data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator|(const CFHE_Integer &other) const {
    FixedPoint o = promote(other, size);
    FixedPoint fp(size);
    for (size_t i = 0; i < size; i++) {
        fp[i] = cfhe_base->GetArithmeticsEngine()->Gate_OR(data[i], o[i]);
    }
    return CFHE_Integer(fp, sign);
}

const CFHE_Integer CFHE_Integer::operator|=(const CFHE_Integer &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    for (size_t i = 0; i < size; i++) {
        data[i] = cfhe_base->GetArithmeticsEngine()->Gate_OR(data[i], o[i]);
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator|(uint64_t other) const {
    CFHE_Integer r(size, sign);
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            r.data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantTrue();
        else
            r.data[i] = COPY_CT(data[i]);
    }
    return r;
}

const CFHE_Integer CFHE_Integer::operator|=(uint64_t other) {
    _sync_var();
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantTrue();
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator^(const CFHE_Integer &other) const {
    FixedPoint o = promote(other, size);
    FixedPoint fp(size);
    for (size_t i = 0; i < size; i++) {
        fp[i] = cfhe_base->GetArithmeticsEngine()->Gate_XOR(data[i], o[i]);
    }
    return CFHE_Integer(fp, sign);
}

const CFHE_Integer CFHE_Integer::operator^=(const CFHE_Integer &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    for (size_t i = 0; i < size; i++) {
        data[i] = cfhe_base->GetArithmeticsEngine()->Gate_XOR(data[i], o[i]);
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator^(uint64_t other) const {
    CFHE_Integer r(size, sign);
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            r.data[i] = cfhe_base->GetArithmeticsEngine()->Gate_NOT(data[i]);
        else
            r.data[i] = COPY_CT(data[i]);
    }
    return r;
}

const CFHE_Integer CFHE_Integer::operator^=(uint64_t other) {
    _sync_var();
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            data[i] = cfhe_base->GetArithmeticsEngine()->Gate_NOT(data[i]);
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator!() const {
    LWECiphertext r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetArithmeticsEngine()->Gate_OR(r, data[i]);
    }
    return CFHE_Integer({cfhe_base->GetArithmeticsEngine()->Gate_NOT(r)},
                        false);
}

const CFHE_Integer CFHE_Integer::operator~() const {
    return *this ^ 0xFFFFFFFFFFFFFFFFUL;
}

const CFHE_Integer CFHE_Integer::operator&&(const CFHE_Integer &other) const {
    LWECiphertext r1 = data[0];
    for (size_t i = 1; i < size; i++) {
        r1 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r1, data[i]);
    }
    LWECiphertext r2 = other.data[0];
    for (size_t i = 1; i < other.size; i++) {
        r2 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r2, other.data[i]);
    }
    return CFHE_Integer({cfhe_base->GetArithmeticsEngine()->Gate_AND(r1, r2)},
                        false);
}

const CFHE_Integer CFHE_Integer::operator&&(uint64_t other) const {
    if (!other)
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->GetConstantFalse()}, false);
    LWECiphertext r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetArithmeticsEngine()->Gate_OR(r, data[i]);
    }
    return CFHE_Integer({r}, false);
}

const CFHE_Integer CFHE_Integer::operator||(const CFHE_Integer &other) const {
    LWECiphertext r1 = data[0];
    for (size_t i = 1; i < size; i++) {
        r1 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r1, data[i]);
    }
    LWECiphertext r2 = other.data[0];
    for (size_t i = 1; i < other.size; i++) {
        r2 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r2, other.data[i]);
    }
    return CFHE_Integer({cfhe_base->GetArithmeticsEngine()->Gate_OR(r1, r2)},
                        false);
}

const CFHE_Integer CFHE_Integer::operator||(uint64_t other) const {
    if (other)
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->GetConstantTrue()}, false);
    LWECiphertext r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetArithmeticsEngine()->Gate_OR(r, data[i]);
    }
    return CFHE_Integer({r}, false);
}

const CFHE_Integer CFHE_Integer::operator++() {
    *this += 1;
    return *this;
}

const CFHE_Integer CFHE_Integer::operator++(int) {
    CFHE_Integer tmp = *this;
    *this += 1;
    return tmp;
}

const CFHE_Integer CFHE_Integer::operator--() {
    *this -= 1;
    return *this;
}

const CFHE_Integer CFHE_Integer::operator--(int) {
    CFHE_Integer tmp = *this;
    *this -= 1;
    return tmp;
}

const CFHE_Integer CFHE_Integer::operator<<(int s) {
    int sz = (int)size;
    FixedPoint fp(size);
    s = clamp<int>(s, 0, size - 1);
    for (int i = sz - 1; i >= 0; i--) {
        fp[i] = (i - s < 0)
                    ? cfhe_base->GetArithmeticsEngine()->GetConstantFalse()
                    : data[i - s];
    }
    return CFHE_Integer(fp, sign);
}

const CFHE_Integer CFHE_Integer::operator<<=(int s) {
    _sync_var();
    int sz = (int)size;
    s = clamp<int>(s, 0, size - 1);
    for (int i = sz - 1; i >= 0; i--) {
        data[i] = (i - s < 0)
                      ? cfhe_base->GetArithmeticsEngine()->GetConstantFalse()
                      : data[i - s];
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator>>(int s) {
    int sz = (int)size;
    FixedPoint fp(size);
    s = clamp<int>(s, 0, size - 1);
    for (int i = 0; i < sz; i++) {
        fp[i] =
            (i + s >= sz)
                ? (sign ? data[fp.size() - 1]
                        : cfhe_base->GetArithmeticsEngine()->GetConstantFalse())
                : data[i + s];
    }
    return CFHE_Integer(fp, sign);
}

const CFHE_Integer CFHE_Integer::operator>>=(int s) {
    _sync_var();
    int sz = (int)size;
    s = clamp<int>(s, 0, size - 1);
    for (int i = 0; i < sz; i++) {
        data[i] =
            (i + s >= sz)
                ? (sign ? data[size - 1]
                        : cfhe_base->GetArithmeticsEngine()->GetConstantFalse())
                : data[i + s];
    }
    _sync_var();
    return *this;
}

CFHE_Integer &CFHE_Integer::operator=(const CFHE_Integer &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = COPY_CT(o[i]);
    }
    _sync_var();
    return *this;
}

CFHE_Integer &CFHE_Integer::operator=(uint64_t other) {
    _sync_var();
    *this = CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign);
    _sync_var();
    return *this;
}

CFHE_Integer::operator bool() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (bool)cfhe_base->DecryptInt(data, size);
}

CFHE_Integer::operator int8_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (int8_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

CFHE_Integer::operator uint8_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (uint8_t)cfhe_base->DecryptInt(data, size);
}

CFHE_Integer::operator int16_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (int16_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

CFHE_Integer::operator uint16_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (uint16_t)cfhe_base->DecryptInt(data, size);
}

CFHE_Integer::operator int32_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (int32_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

CFHE_Integer::operator uint32_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (uint32_t)cfhe_base->DecryptInt(data, size);
}

CFHE_Integer::operator int64_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (int64_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

CFHE_Integer::operator uint64_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (uint64_t)cfhe_base->DecryptInt(data, size);
}

CFHE_Integer::operator double() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (double)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

ostream &computefhe::operator<<(ostream &out, const CFHE_Integer &obj) {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    if (obj.sign) {
        out << CFHE_Integer::sign_extend(
            cfhe_base->DecryptInt(obj.data, obj.size), obj.size);
    } else {
        out << (uint64_t)(cfhe_base->DecryptInt(obj.data, obj.size));
    }
    return out;
}
