#include <computefhe/ComputeFHE.h>
#include <computefhe/Efixedpoint.h>

using namespace computefhe;

FixedPoint Efixedpoint::double2fp(double d, size_t n_digits, size_t n_frac) {
    double d_abs = std::abs(d);
    uint64_t i = (uint64_t)d_abs;
    uint64_t q = (int64_t)((d_abs - i) * (1 << n_frac));
    int64_t r = ((i << n_frac) | q) * ((d < 0) ? -1 : 1);
    return cfhe_base->GetConstantInt(r, n_digits);
}

void Efixedpoint::promote(const Efixedpoint &a, const Efixedpoint &b,
                          FixedPoint &a_out, FixedPoint &b_out,
                          size_t &n_digits_out, size_t &n_frac_out,
                          bool &sign_out) {
    if (a.size == b.size && a.frac_size == b.frac_size) {
        a_out = a.data;
        b_out = b.data;
        n_digits_out = a.size;
        n_frac_out = a.frac_size;
        sign_out = a.sign && b.sign;
        return;
    }

    size_t a_i_size = a.size - a.frac_size;
    size_t b_i_size = b.size - b.frac_size;
    bool cond = a_i_size >= b_i_size ||
                (a_i_size == b_i_size && a.frac_size > b.frac_size);
    n_digits_out = cond ? a.size : b.size;
    n_frac_out = cond ? a.frac_size : b.frac_size;
    sign_out = cond ? a.sign : b.sign;

    int a_f_sh = (int)n_frac_out - (int)a.frac_size;
    int b_f_sh = (int)n_frac_out - (int)b.frac_size;

    a_out.resize(n_digits_out);
    b_out.resize(n_digits_out);

    BinaryDigit last_a = a.data.back();
    BinaryDigit last_b = b.data.back();

    for (size_t i = 0; i < n_digits_out; i++) {
        int ai = i - a_f_sh;
        int bi = i - b_f_sh;

        if (ai >= 0 && ai < (int)a.size)
            a_out[i] = a.data[ai];
        else if (ai < 0)
            a_out[i] = cfhe_base->GetALU()->Constant0();
        else if (a.sign)
            a_out[i] = last_a;
        else
            a_out[i] = cfhe_base->GetALU()->Constant0();

        if (bi >= 0 && bi < (int)b.size)
            b_out[i] = b.data[bi];
        else if (bi < 0)
            b_out[i] = cfhe_base->GetALU()->Constant0();
        else if (b.sign)
            b_out[i] = last_b;
        else
            b_out[i] = cfhe_base->GetALU()->Constant0();
    }
}

FixedPoint Efixedpoint::promote(const Efixedpoint &a, size_t n_digits,
                                size_t n_frac) {
    if (a.size == n_digits && a.frac_size == n_frac) {
        return FixedPoint(a.data);
    }

    int a_f_sh = (int)n_frac - (int)a.frac_size;
    FixedPoint out(n_digits);
    BinaryDigit last_a = a.data.back();

    for (size_t i = 0; i < n_digits; i++) {
        int ai = i - a_f_sh;
        if (ai >= 0 && ai < (int)a.size)
            out[i] = a.data[ai];
        else if (ai < 0)
            out[i] = cfhe_base->GetALU()->Constant0();
        else if (a.sign)
            out[i] = last_a;
        else
            out[i] = cfhe_base->GetALU()->Constant0();
    }
    return out;
}

Efixedpoint::Efixedpoint() : Efixedpoint(8, 4, true) {}

Efixedpoint::Efixedpoint(size_t n_digits, size_t n_frac, bool is_signed)
    : Einteger(n_digits, is_signed) {
    frac_size = n_frac < n_digits ? n_frac : n_digits;
}

Efixedpoint::Efixedpoint(double d, size_t n_digits, size_t n_frac,
                         bool is_signed)
    : Einteger(n_digits, is_signed) {
    frac_size = n_frac < n_digits ? n_frac : n_digits;
    data = double2fp(d, n_digits, frac_size);
}

Efixedpoint::Efixedpoint(const FixedPoint &fp, size_t n_frac, bool is_signed)
    : Einteger(fp, is_signed) {
    frac_size = n_frac < fp.size() ? n_frac : fp.size();
}

Efixedpoint::Efixedpoint(const Efixedpoint &other) : Einteger(other) {
    frac_size = other.frac_size;
}

Efixedpoint::Efixedpoint(const Einteger &other) : Einteger(other) {
    frac_size = 0;
}

size_t Efixedpoint::getFracSize() const { return frac_size; }

void Efixedpoint::setFracSize(size_t n_frac) {
    frac_size = n_frac < size ? n_frac : size;
}

const Einteger Efixedpoint::operator==(const Efixedpoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp({cfhe_base->GetALU()->CmpEq(a, b)});
    return Einteger(fp, false);
}

const Einteger Efixedpoint::operator!=(const Efixedpoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp({cfhe_base->GetALU()->CmpNotEq(a, b)});
    return Einteger(fp, false);
}

const Einteger Efixedpoint::operator>(const Efixedpoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp({(sign && other.sign) ? cfhe_base->GetALU()->CmpGT(a, b)
                                        : cfhe_base->GetALU()->CmpGT_U(a, b)});
    return Einteger(fp, false);
}

const Einteger Efixedpoint::operator>=(const Efixedpoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp({(sign && other.sign)
                       ? cfhe_base->GetALU()->CmpGTEq(a, b)
                       : cfhe_base->GetALU()->CmpGTEq_U(a, b)});
    return Einteger(fp, false);
}

const Einteger Efixedpoint::operator<(const Efixedpoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp({(sign && other.sign) ? cfhe_base->GetALU()->CmpLT(a, b)
                                        : cfhe_base->GetALU()->CmpLT_U(a, b)});
    return Einteger(fp, false);
}

const Einteger Efixedpoint::operator<=(const Efixedpoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp({(sign && other.sign)
                       ? cfhe_base->GetALU()->CmpLTEq(a, b)
                       : cfhe_base->GetALU()->CmpLTEq_U(a, b)});
    return Einteger(fp, false);
}

const Einteger Efixedpoint::operator==(double other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this == Efixedpoint(other, size, frac_size, sign);
}

const Einteger Efixedpoint::operator!=(double other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this != Efixedpoint(other, size, frac_size, sign);
}

const Einteger Efixedpoint::operator>(double other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this > Efixedpoint(other, size, frac_size, sign);
}

const Einteger Efixedpoint::operator>=(double other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this >= Efixedpoint(other, size, frac_size, sign);
}

const Einteger Efixedpoint::operator<(double other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this < Efixedpoint(other, size, frac_size, sign);
}

const Einteger Efixedpoint::operator<=(double other) const {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this <= Efixedpoint(other, size, frac_size, sign);
}

const Efixedpoint Efixedpoint::operator+(const Efixedpoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp(cfhe_base->GetALU()->AddNC(a, b));
    return Efixedpoint(fp, n_frac, sign);
}

const Efixedpoint Efixedpoint::operator+=(const Efixedpoint &other) {
    _sync_var();
    FixedPoint o = promote(other, size, frac_size);
    data = cfhe_base->GetALU()->AddNC(data, o);
    _sync_var();
    return *this;
}

const Efixedpoint Efixedpoint::operator+(double other) const {
    // TODO: optimize this by using ciphertext-plaintext operation
    return *this + Efixedpoint(other, size, frac_size, sign);
}

const Efixedpoint Efixedpoint::operator+=(double other) {
    // TODO: optimize this by using ciphertext-plaintext operation
    return *this += Efixedpoint(other, size, frac_size, sign);
}

const Efixedpoint Efixedpoint::operator-(const Efixedpoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp(cfhe_base->GetALU()->SubNC(a, b));
    return Efixedpoint(fp, n_frac, sign);
}

const Efixedpoint Efixedpoint::operator-=(const Efixedpoint &other) {
    _sync_var();
    FixedPoint o = promote(other, size, frac_size);
    data = cfhe_base->GetALU()->SubNC(data, o);
    _sync_var();
    return *this;
}

const Efixedpoint Efixedpoint::operator-(double other) const {
    // TODO: optimize this by using ciphertext-plaintext operation
    return *this - Efixedpoint(other, size, frac_size, sign);
}

const Efixedpoint Efixedpoint::operator-=(double other) {
    // TODO: optimize this by using ciphertext-plaintext operation
    return *this -= Efixedpoint(other, size, frac_size, sign);
}

const Efixedpoint Efixedpoint::operator*(const Efixedpoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    size_t mul_frac_a = n_frac >> 1;
    size_t mul_frac_b = n_frac - mul_frac_a;
    a.erase(a.begin(), a.begin() + mul_frac_b);
    b.erase(b.begin(), b.begin() + mul_frac_a);
    a = promote(Efixedpoint(a, mul_frac_a, sign), n_digits, mul_frac_a);
    b = promote(Efixedpoint(b, mul_frac_b, sign), n_digits, mul_frac_b);
    FixedPoint fp(cfhe_base->GetALU()->Mul(a, b));
    return Efixedpoint(fp, n_frac, sign);
}

const Efixedpoint Efixedpoint::operator*=(const Efixedpoint &other) {
    _sync_var();
    FixedPoint o = promote(other, size, frac_size);
    size_t mul_frac_a = frac_size >> 1;
    size_t mul_frac_b = frac_size - mul_frac_a;
    FixedPoint d(data.begin() + mul_frac_b, data.end());
    o.erase(o.begin(), o.begin() + mul_frac_a);
    d = promote(Efixedpoint(d, mul_frac_a, sign), size, mul_frac_a);
    o = promote(Efixedpoint(o, mul_frac_b, sign), size, mul_frac_b);
    data = cfhe_base->GetALU()->Mul(d, o);
    _sync_var();
    return *this;
}

const Efixedpoint Efixedpoint::operator*(double other) const {
    // TODO: optimize this by using ciphertext-plaintext operation
    return *this * Efixedpoint(other, size, frac_size, sign);
}

const Efixedpoint Efixedpoint::operator*=(double other) {
    // TODO: optimize this by using ciphertext-plaintext operation
    return *this *= Efixedpoint(other, size, frac_size, sign);
}

const Efixedpoint Efixedpoint::operator/(const Efixedpoint &other) const {
    FixedPoint a, b, q, r;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    b = cfhe_base->GetALU()->ShiftRight(b, n_frac >> 1);
    cfhe_base->GetALU()->DivU(a, b, q, r);
    q = cfhe_base->GetALU()->ShiftLeft(q, n_frac - (n_frac >> 1));
    return Efixedpoint(q, n_frac, sign);
}

const Efixedpoint Efixedpoint::operator/=(const Efixedpoint &other) {
    _sync_var();
    FixedPoint q, r;
    FixedPoint o = promote(other, size, frac_size);
    o = cfhe_base->GetALU()->ShiftRight(o, frac_size >> 1);
    cfhe_base->GetALU()->DivU(data, o, q, r);
    data = cfhe_base->GetALU()->ShiftLeft(q, frac_size - (frac_size >> 1));
    _sync_var();
    return *this;
}

const Efixedpoint Efixedpoint::operator/(double other) const {
    // TODO: optimize this by using ciphertext-plaintext operation
    return *this / Efixedpoint(other, size, frac_size, sign);
}

const Efixedpoint Efixedpoint::operator/=(double other) {
    // TODO: optimize this by using ciphertext-plaintext operation
    return *this /= Efixedpoint(other, size, frac_size, sign);
}

const Efixedpoint computefhe::operator/(double a, const Efixedpoint &b) {
    // TODO: optimize this by using ciphertext-plaintext operation
    return Efixedpoint(a, b.size, b.frac_size, b.sign) / b;
}

const Efixedpoint Efixedpoint::operator-() const {
    return Efixedpoint(cfhe_base->GetALU()->Neg(data), frac_size, sign);
}

const Efixedpoint Efixedpoint::operator++() {
    *this += 1.;
    return *this;
}

const Efixedpoint Efixedpoint::operator++(int) {
    Einteger tmp = *this;
    *this += 1.;
    return tmp;
}

const Efixedpoint Efixedpoint::operator--() {
    *this -= 1.;
    return *this;
}

const Efixedpoint Efixedpoint::operator--(int) {
    Einteger tmp = *this;
    *this -= 1.;
    return tmp;
}

const Efixedpoint Efixedpoint::operator<<(int i) const {
    Einteger res = this->Einteger::operator<<(i);
    return Efixedpoint(res.getData(), frac_size, sign);
}

const Efixedpoint Efixedpoint::operator<<=(int i) {
    static_cast<Einteger &>(*this) <<= i;
    return *this;
}

const Efixedpoint Efixedpoint::operator>>(int i) const {
    Einteger res = this->Einteger::operator>>(i);
    return Efixedpoint(res.getData(), frac_size, sign);
}

const Efixedpoint Efixedpoint::operator>>=(int i) {
    static_cast<Einteger &>(*this) >>= i;
    return *this;
}

Efixedpoint &Efixedpoint::operator=(const Efixedpoint &other) {
    _sync_var();
    FixedPoint o = promote(other, size, frac_size);
    data = o;
    _sync_var();
    return *this;
}

Efixedpoint &Efixedpoint::operator=(double other) {
    _sync_var();
    *this = Efixedpoint(other, size, frac_size, sign);
    _sync_var();
    return *this;
}

Efixedpoint::operator double() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    if (sign) {
        return (double)Einteger::sign_extend(cfhe_base->DecryptInt(data, size),
                                             size) /
               (1 << frac_size);
    } else {
        return (double)cfhe_base->DecryptInt(data, size) / (1 << frac_size);
    }
}

Einteger Efixedpoint::toInteger() const {
    return Einteger(FixedPoint(data.begin() + frac_size, data.end()), sign);
}

ostream &computefhe::operator<<(ostream &out, const Efixedpoint &obj) {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    if (obj.sign) {
        out << (double)Einteger::sign_extend(
                   cfhe_base->DecryptInt(obj.data, obj.size), obj.size) /
                   (1 << obj.frac_size);
    } else {
        out << (double)cfhe_base->DecryptInt(obj.data, obj.size) /
                   (1 << obj.frac_size);
    }
    return out;
}
