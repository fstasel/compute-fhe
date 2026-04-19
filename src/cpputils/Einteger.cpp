#include <computefhe/ComputeFHE.h>
#include <computefhe/Einteger.h>

using namespace computefhe;

namespace computefhe {
    FixedPoint Einteger::cached_divident;
    FixedPoint Einteger::cached_divisor;
    FixedPoint Einteger::cached_quotient;
    FixedPoint Einteger::cached_remainder;
} // namespace computefhe

int64_t Einteger::sign_extend(uint64_t d, size_t n_digits) {
    if (n_digits == 0 || n_digits >= 64)
        return (int64_t)d;
    uint64_t mask = 1ULL << (n_digits - 1);
    return (int64_t)((d ^ mask) - mask);
}

void Einteger::_sync_var() {
    if (ConditionManager::conditional_mode()) {
        ConditionManager::register_variable((void *)this, &data);
    }
}

void Einteger::_desync_var() {
    if (ConditionManager::conditional_mode()) {
        ConditionManager::unregister_variable((void *)this);
    }
}

bool Einteger::promote(const Einteger &a, const Einteger &b, FixedPoint &a_out,
                       FixedPoint &b_out) {
    if (a.size == b.size) {
        a_out = a.data;
        b_out = b.data;
        return a.sign && b.sign;
    }

    size_t n = (a.size > b.size) ? a.size : b.size;
    bool s = (a.size > b.size) ? a.sign : b.sign;
    a_out.resize(n);
    b_out.resize(n);

    BinaryDigit last_a = a.data.back();
    BinaryDigit last_b = b.data.back();

    for (size_t i = 0; i < n; i++) {
        if (i < a.size)
            a_out[i] = a.data[i];
        else if (a.sign)
            a_out[i] = last_a;
        else
            a_out[i] = cfhe_base->GetALU()->Constant0();

        if (i < b.size)
            b_out[i] = b.data[i];
        else if (b.sign)
            b_out[i] = last_b;
        else
            b_out[i] = cfhe_base->GetALU()->Constant0();
    }
    return s;
}

FixedPoint Einteger::promote(const Einteger &a, size_t s) {
    if (a.size == s) {
        return FixedPoint(a.data);
    }
    FixedPoint out(s);
    BinaryDigit last = a.data.back();
    for (size_t i = 0; i < s; i++) {
        if (i < a.size)
            out[i] = a.data[i];
        else if (a.sign)
            out[i] = last;
        else
            out[i] = cfhe_base->GetALU()->Constant0();
    }
    return out;
}

Einteger::Einteger() : Einteger(8, false) {}

Einteger::Einteger(int64_t d) : Einteger(d, 8) {}

Einteger::Einteger(size_t n_digits, bool is_signed) {
    if (cfhe_base == nullptr)
        Init();
    if (CLIENT_MODE) {
        data = cfhe_base->EncryptInt(0, n_digits);
    } else {
        data = cfhe_base->GetConstantInt(0, n_digits);
    }
    size = n_digits;
    sign = is_signed;
}

Einteger::Einteger(int64_t d, size_t n_digits) {
    if (cfhe_base == nullptr)
        Init();
    if (CLIENT_MODE) {
        data = cfhe_base->EncryptInt((uint64_t)d, n_digits);
    } else {
        data = cfhe_base->GetConstantInt((uint64_t)d, n_digits);
    }
    size = n_digits;
    sign = true;
}

Einteger::Einteger(uint64_t d, size_t n_digits) {
    if (cfhe_base == nullptr)
        Init();
    if (CLIENT_MODE) {
        data = cfhe_base->EncryptInt(d, n_digits);
    } else {
        data = cfhe_base->GetConstantInt(d, n_digits);
    }
    size = n_digits;
    sign = false;
}

Einteger::Einteger(const FixedPoint &fp, bool is_signed) {
    if (cfhe_base == nullptr)
        Init();
    data = fp;
    size = fp.size();
    sign = is_signed;
}

Einteger::Einteger(const Einteger &other) {
    if (cfhe_base == nullptr)
        Init();
    data.resize(other.size);
    data = other.data;
    size = other.size;
    sign = other.sign;
}

Einteger::~Einteger() { _desync_var(); }

const FixedPoint &Einteger::getData() const { return data; }

size_t Einteger::getSize() const { return size; }

bool Einteger::isSigned() const { return sign; }

const Einteger Einteger::operator==(const Einteger &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp((vector<BinaryDigit>){cfhe_base->GetALU()->CmpEq(a, b)});
    return Einteger(fp, false);
}

const Einteger Einteger::operator!=(const Einteger &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp((vector<BinaryDigit>){cfhe_base->GetALU()->CmpNotEq(a, b)});
    return Einteger(fp, false);
}

const Einteger Einteger::operator>(const Einteger &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp((vector<BinaryDigit>){
        (sign && other.sign) ? cfhe_base->GetALU()->CmpGT(a, b)
                             : cfhe_base->GetALU()->CmpGT_U(a, b)});
    return Einteger(fp, false);
}

const Einteger Einteger::operator>=(const Einteger &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp((vector<BinaryDigit>){
        (sign && other.sign) ? cfhe_base->GetALU()->CmpGTEq(a, b)
                             : cfhe_base->GetALU()->CmpGTEq_U(a, b)});
    return Einteger(fp, false);
}

const Einteger Einteger::operator<(const Einteger &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp((vector<BinaryDigit>){
        (sign && other.sign) ? cfhe_base->GetALU()->CmpLT(a, b)
                             : cfhe_base->GetALU()->CmpLT_U(a, b)});
    return Einteger(fp, false);
}

const Einteger Einteger::operator<=(const Einteger &other) const {
    FixedPoint a, b;
    promote(*this, other, a, b);
    FixedPoint fp((vector<BinaryDigit>){
        (sign && other.sign) ? cfhe_base->GetALU()->CmpLTEq(a, b)
                             : cfhe_base->GetALU()->CmpLTEq_U(a, b)});
    return Einteger(fp, false);
}

const Einteger Einteger::operator==(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp((vector<BinaryDigit>){cfhe_base->GetALU()->CmpEq(
        data, cfhe_base->GetConstantInt(other, size))});
    return Einteger(fp, false);
}

const Einteger Einteger::operator!=(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp((vector<BinaryDigit>){cfhe_base->GetALU()->CmpNotEq(
        data, cfhe_base->GetConstantInt(other, size))});
    return Einteger(fp, false);
}

const Einteger Einteger::operator>(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp((vector<BinaryDigit>){
        sign ? cfhe_base->GetALU()->CmpGT(
                   data, cfhe_base->GetConstantInt(other, size))
             : cfhe_base->GetALU()->CmpGT_U(
                   data, cfhe_base->GetConstantInt(other, size))});
    return Einteger(fp, false);
}

const Einteger Einteger::operator>=(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp((vector<BinaryDigit>){
        sign ? cfhe_base->GetALU()->CmpGTEq(
                   data, cfhe_base->GetConstantInt(other, size))
             : cfhe_base->GetALU()->CmpGTEq_U(
                   data, cfhe_base->GetConstantInt(other, size))});
    return Einteger(fp, false);
}

const Einteger Einteger::operator<(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp((vector<BinaryDigit>){
        sign ? cfhe_base->GetALU()->CmpLT(
                   data, cfhe_base->GetConstantInt(other, size))
             : cfhe_base->GetALU()->CmpLT_U(
                   data, cfhe_base->GetConstantInt(other, size))});
    return Einteger(fp, false);
}

const Einteger Einteger::operator<=(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    FixedPoint fp((vector<BinaryDigit>){
        sign ? cfhe_base->GetALU()->CmpLTEq(
                   data, cfhe_base->GetConstantInt(other, size))
             : cfhe_base->GetALU()->CmpLTEq_U(
                   data, cfhe_base->GetConstantInt(other, size))});
    return Einteger(fp, false);
}

const Einteger Einteger::operator+(const Einteger &other) const {
    FixedPoint a, b;
    bool s = promote(*this, other, a, b);
    FixedPoint fp(cfhe_base->GetALU()->AddNC(a, b));
    return Einteger(fp, s);
}

const Einteger Einteger::operator+=(const Einteger &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    data = cfhe_base->GetALU()->AddNC(data, o);
    _sync_var();
    return *this;
}

const Einteger Einteger::operator-(const Einteger &other) const {
    FixedPoint a, b;
    bool s = promote(*this, other, a, b);
    FixedPoint fp(cfhe_base->GetALU()->SubNC(a, b));
    return Einteger(fp, s);
}

const Einteger Einteger::operator-=(const Einteger &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    data = cfhe_base->GetALU()->SubNC(data, o);
    _sync_var();
    return *this;
}

const Einteger Einteger::operator*(const Einteger &other) const {
    FixedPoint a, b;
    bool s = promote(*this, other, a, b);
    FixedPoint fp(cfhe_base->GetALU()->Mul(a, b));
    return Einteger(fp, s);
}

const Einteger Einteger::operator*=(const Einteger &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    data = cfhe_base->GetALU()->Mul(data, o);
    _sync_var();
    return *this;
}

bool Einteger::div_cache(const FixedPoint &a, const FixedPoint &b) {
    if (cached_divident.size() != a.size() || cached_divisor.size() != b.size())
        return false;

    for (size_t i = 0; i < a.size(); i++) {
        if (cached_divident[i] != a[i])
            return false;
    }
    for (size_t i = 0; i < b.size(); i++) {
        if (cached_divisor[i] != b[i])
            return false;
    }
    return true;
}

bool Einteger::div_cache(const FixedPoint &a, uint64_t b) {
    static uint64_t cached_b = 0;
    if (cached_divident.size() != a.size() || cached_b != b) {
        cached_b = b;
        return false;
    }
    for (size_t i = 0; i < a.size(); i++) {
        if (cached_divident[i] != a[i]) {
            return false;
        }
    }
    return true;
}

bool Einteger::div_cache(uint64_t a, const FixedPoint &b) {
    static uint64_t cached_a = 0;
    if (cached_a != a || cached_divisor.size() != b.size()) {
        cached_a = a;
        return false;
    }
    for (size_t i = 0; i < b.size(); i++) {
        if (cached_divisor[i] != b[i]) {
            return false;
        }
    }
    return true;
}

const Einteger Einteger::operator/(const Einteger &other) const {
    FixedPoint a, b;
    bool s = promote(*this, other, a, b);
    if (div_cache(data, other.data)) {
        return Einteger(cached_quotient, s);
    }
    cached_divident = data;
    cached_divisor = other.data;
    cfhe_base->GetALU()->DivU(a, b, cached_quotient, cached_remainder);
    return Einteger(cached_quotient, s);
}

const Einteger Einteger::operator/=(const Einteger &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    if (div_cache(data, other.data)) {
        data = cached_quotient;
        _sync_var();
        return *this;
    }
    cached_divident = data;
    cached_divisor = other.data;
    cfhe_base->GetALU()->DivU(data, o, cached_quotient, cached_remainder);
    data = cached_quotient;
    _sync_var();
    return *this;
}

const Einteger Einteger::operator%(const Einteger &other) const {
    FixedPoint a, b;
    bool s = promote(*this, other, a, b);
    if (div_cache(data, other.data)) {
        return Einteger(cached_remainder, s);
    }
    cached_divident = data;
    cached_divisor = other.data;
    cfhe_base->GetALU()->DivU(a, b, cached_quotient, cached_remainder);
    return Einteger(cached_remainder, s);
}

const Einteger Einteger::operator%=(const Einteger &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    if (div_cache(data, other.data)) {
        data = cached_remainder;
        _sync_var();
        return *this;
    }
    cached_divident = data;
    cached_divisor = other.data;
    cfhe_base->GetALU()->DivU(data, o, cached_quotient, cached_remainder);
    data = cached_remainder;
    _sync_var();
    return *this;
}

const Einteger Einteger::operator+(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this + Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator+=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this += Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator-(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this - Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator-=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this -= Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator*(uint64_t other) const {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this * Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator*=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this *= Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator/(uint64_t other) const {
    if (div_cache(data, other)) {
        return Einteger(cached_quotient, sign);
    }
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    FixedPoint o = cfhe_base->GetConstantInt(other, size);
    cached_divident = data;
    cached_divisor = o;
    cfhe_base->GetALU()->DivU(data, o, cached_quotient, cached_remainder);
    return Einteger(cached_quotient, sign);
}

const Einteger Einteger::operator/=(uint64_t other) {
    _sync_var();
    if (div_cache(data, other)) {
        data = cached_quotient;
        _sync_var();
        return *this;
    }
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    FixedPoint o = cfhe_base->GetConstantInt(other, size);
    cached_divident = data;
    cached_divisor = o;
    cfhe_base->GetALU()->DivU(data, o, cached_quotient, cached_remainder);
    data = cached_quotient;
    _sync_var();
    return *this;
}

const Einteger Einteger::operator%(uint64_t other) const {
    if (div_cache(data, other)) {
        return Einteger(cached_remainder, sign);
    }
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    FixedPoint o = cfhe_base->GetConstantInt(other, size);
    cached_divident = data;
    cached_divisor = o;
    cfhe_base->GetALU()->DivU(data, o, cached_quotient, cached_remainder);
    return Einteger(cached_remainder, sign);
}

const Einteger Einteger::operator%=(uint64_t other) {
    _sync_var();
    if (div_cache(data, other)) {
        data = cached_remainder;
        _sync_var();
        return *this;
    }
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    FixedPoint o = cfhe_base->GetConstantInt(other, size);
    cached_divident = data;
    cached_divisor = o;
    cfhe_base->GetALU()->DivU(data, o, cached_quotient, cached_remainder);
    data = cached_remainder;
    _sync_var();
    return *this;
}

const Einteger computefhe::operator/(uint64_t a, const Einteger &b) {
    if (Einteger::div_cache(a, b.data)) {
        return Einteger(Einteger::cached_quotient, b.sign);
    }
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    FixedPoint o = cfhe_base->GetConstantInt(a, b.size);
    Einteger::cached_divident = o;
    Einteger::cached_divisor = b.data;
    cfhe_base->GetALU()->DivU(o, b.data, Einteger::cached_quotient,
                              Einteger::cached_remainder);
    return Einteger(Einteger::cached_quotient, b.sign);
}

const Einteger computefhe::operator%(uint64_t a, const Einteger &b) {
    if (Einteger::div_cache(a, b.data)) {
        return Einteger(Einteger::cached_remainder, b.sign);
    }
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    FixedPoint o = cfhe_base->GetConstantInt(a, b.size);
    Einteger::cached_divident = o;
    Einteger::cached_divisor = b.data;
    cfhe_base->GetALU()->DivU(o, b.data, Einteger::cached_quotient,
                              Einteger::cached_remainder);
    return Einteger(Einteger::cached_remainder, b.sign);
}

const Einteger Einteger::operator-() const {
    return Einteger(cfhe_base->GetALU()->Neg(data), sign);
}

const Einteger Einteger::operator&(const Einteger &other) const {
    FixedPoint o = promote(other, size);
    FixedPoint fp(size);
    for (size_t i = 0; i < size; i++) {
        fp[i] = cfhe_base->GetALU()->Gate_AND(data[i], o[i]);
    }
    return Einteger(fp, sign);
}

const Einteger Einteger::operator&=(const Einteger &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    for (size_t i = 0; i < size; i++) {
        data[i] = cfhe_base->GetALU()->Gate_AND(data[i], o[i]);
    }
    _sync_var();
    return *this;
}

const Einteger Einteger::operator&(uint64_t other) const {
    return *this & Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator&=(uint64_t other) {
    return *this &= Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator|(const Einteger &other) const {
    FixedPoint o = promote(other, size);
    FixedPoint fp(size);
    for (size_t i = 0; i < size; i++) {
        fp[i] = cfhe_base->GetALU()->Gate_OR(data[i], o[i]);
    }
    return Einteger(fp, sign);
}

const Einteger Einteger::operator|=(const Einteger &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    for (size_t i = 0; i < size; i++) {
        data[i] = cfhe_base->GetALU()->Gate_OR(data[i], o[i]);
    }
    _sync_var();
    return *this;
}

const Einteger Einteger::operator|(uint64_t other) const {
    return *this | Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator|=(uint64_t other) {
    return *this |= Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator^(const Einteger &other) const {
    FixedPoint o = promote(other, size);
    FixedPoint fp(size);
    for (size_t i = 0; i < size; i++) {
        fp[i] = cfhe_base->GetALU()->Gate_XOR(data[i], o[i]);
    }
    return Einteger(fp, sign);
}

const Einteger Einteger::operator^=(const Einteger &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    for (size_t i = 0; i < size; i++) {
        data[i] = cfhe_base->GetALU()->Gate_XOR(data[i], o[i]);
    }
    _sync_var();
    return *this;
}

const Einteger Einteger::operator^(uint64_t other) const {
    return *this ^ Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator^=(uint64_t other) {
    return *this ^= Einteger(cfhe_base->GetConstantInt(other, size), sign);
}

const Einteger Einteger::operator!() const {
    BinaryDigit r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetALU()->Gate_OR(r, data[i]);
    }
    return Einteger(FixedPoint({cfhe_base->GetALU()->Gate_NOT(r)}), false);
}

const Einteger Einteger::operator~() const {
    return *this ^ 0xFFFFFFFFFFFFFFFFUL;
}

const Einteger Einteger::operator&&(const Einteger &other) const {
    BinaryDigit r1 = data[0];
    for (size_t i = 1; i < size; i++) {
        r1 = cfhe_base->GetALU()->Gate_OR(r1, data[i]);
    }
    BinaryDigit r2 = other.data[0];
    for (size_t i = 1; i < other.size; i++) {
        r2 = cfhe_base->GetALU()->Gate_OR(r2, other.data[i]);
    }
    return Einteger(FixedPoint({cfhe_base->GetALU()->Gate_AND(r1, r2)}), false);
}

const Einteger Einteger::operator&&(uint64_t other) const {
    if (!other)
        return Einteger(FixedPoint({cfhe_base->GetALU()->Constant0()}), false);
    BinaryDigit r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetALU()->Gate_OR(r, data[i]);
    }
    return Einteger(FixedPoint({r}), false);
}

const Einteger Einteger::operator||(const Einteger &other) const {
    BinaryDigit r1 = data[0];
    for (size_t i = 1; i < size; i++) {
        r1 = cfhe_base->GetALU()->Gate_OR(r1, data[i]);
    }
    BinaryDigit r2 = other.data[0];
    for (size_t i = 1; i < other.size; i++) {
        r2 = cfhe_base->GetALU()->Gate_OR(r2, other.data[i]);
    }
    return Einteger(FixedPoint({cfhe_base->GetALU()->Gate_OR(r1, r2)}), false);
}

const Einteger Einteger::operator||(uint64_t other) const {
    if (other)
        return Einteger(FixedPoint({cfhe_base->GetALU()->Constant1()}), false);
    BinaryDigit r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetALU()->Gate_OR(r, data[i]);
    }
    return Einteger(FixedPoint({r}), false);
}

const Einteger Einteger::operator++() {
    *this += 1;
    return *this;
}

const Einteger Einteger::operator++(int) {
    Einteger tmp = *this;
    *this += 1;
    return tmp;
}

const Einteger Einteger::operator--() {
    *this -= 1;
    return *this;
}

const Einteger Einteger::operator--(int) {
    Einteger tmp = *this;
    *this -= 1;
    return tmp;
}

const Einteger Einteger::operator<<(int s) const {
    return Einteger(cfhe_base->GetALU()->ShiftLeft(data, s), sign);
}

const Einteger Einteger::operator<<=(int s) {
    _sync_var();
    data = cfhe_base->GetALU()->ShiftLeft(data, s);
    _sync_var();
    return *this;
}

const Einteger Einteger::operator>>(int s) const {
    return Einteger(cfhe_base->GetALU()->ShiftRight(data, s, sign), sign);
}

const Einteger Einteger::operator>>=(int s) {
    _sync_var();
    data = cfhe_base->GetALU()->ShiftRight(data, s, sign);
    _sync_var();
    return *this;
}

Einteger &Einteger::operator=(const Einteger &other) {
    _sync_var();
    FixedPoint o = promote(other, size);
    data = o;
    _sync_var();
    return *this;
}

Einteger &Einteger::operator=(uint64_t other) {
    _sync_var();
    if (CLIENT_MODE) {
        *this = Einteger(cfhe_base->EncryptInt(other, size), sign);
    } else {
        *this = Einteger(cfhe_base->GetConstantInt(other, size), sign);
    }
    _sync_var();
    return *this;
}

Einteger::operator bool() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (bool)cfhe_base->DecryptInt(data, size);
}

Einteger::operator int8_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (int8_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

Einteger::operator uint8_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (uint8_t)cfhe_base->DecryptInt(data, size);
}

Einteger::operator int16_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (int16_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

Einteger::operator uint16_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (uint16_t)cfhe_base->DecryptInt(data, size);
}

Einteger::operator int32_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (int32_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

Einteger::operator uint32_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (uint32_t)cfhe_base->DecryptInt(data, size);
}

Einteger::operator int64_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (int64_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

Einteger::operator uint64_t() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (uint64_t)cfhe_base->DecryptInt(data, size);
}

Einteger::operator double() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    return (double)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

ostream &computefhe::operator<<(ostream &out, const Einteger &obj) {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    if (obj.sign) {
        out << Einteger::sign_extend(cfhe_base->DecryptInt(obj.data, obj.size),
                                     obj.size);
    } else {
        out << (uint64_t)(cfhe_base->DecryptInt(obj.data, obj.size));
    }
    return out;
}

// Explicitly instantiate EInt variants for standard types
template class EInt<bool, 1, false>;
template class EInt<int8_t, 8, true>;
template class EInt<uint8_t, 8, false>;
template class EInt<int16_t, 16, true>;
template class EInt<uint16_t, 16, false>;
template class EInt<int32_t, 32, true>;
template class EInt<uint32_t, 32, false>;
template class EInt<int64_t, 64, true>;
template class EInt<uint64_t, 64, false>;

// TODO: Ebool operators must behave differently
// bool op integral_t -> (int)bool op integral_t -> Promoted ->
// (bool)Promoted (bool)x = 0 if x == 0, else 1
