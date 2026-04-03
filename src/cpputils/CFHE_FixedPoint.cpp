#include <computefhe/CFHE_FixedPoint.h>

using namespace computefhe;

FixedPoint CFHE_FixedPoint::double2fp(double d, size_t n_digits,
                                      size_t n_frac) {
    double d_abs = std::abs(d);
    uint64_t i = (uint64_t)d_abs;
    uint64_t q = (int64_t)((d_abs - i) * (1 << n_frac));
    int64_t r = ((i << n_frac) | q) * ((d < 0) ? -1 : 1);
    return cfhe_base->GetConstantInt(r, n_digits);
}

void CFHE_FixedPoint::promote(const CFHE_FixedPoint &a,
                              const CFHE_FixedPoint &b, FixedPoint &a_out,
                              FixedPoint &b_out, size_t &n_digits_out,
                              size_t &n_frac_out, bool &sign_out) {
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

    LWECiphertext last_a = a.data.back();
    LWECiphertext last_b = b.data.back();

    for (size_t i = 0; i < n_digits_out; i++) {
        int ai = i - a_f_sh;
        int bi = i - b_f_sh;

        if (ai >= 0 && ai < (int)a.size)
            a_out[i] = a.data[ai];
        else if (ai < 0)
            a_out[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
        else if (a.sign)
            a_out[i] = last_a;
        else
            a_out[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();

        if (bi >= 0 && bi < (int)b.size)
            b_out[i] = b.data[bi];
        else if (bi < 0)
            b_out[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
        else if (b.sign)
            b_out[i] = last_b;
        else
            b_out[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
}

FixedPoint CFHE_FixedPoint::promote(const CFHE_FixedPoint &a, size_t n_digits,
                                    size_t n_frac) {
    if (a.size == n_digits && a.frac_size == n_frac) {
        return FixedPoint(a.data);
    }

    int a_f_sh = (int)n_frac - (int)a.frac_size;
    FixedPoint out(n_digits);
    LWECiphertext last_a = a.data.back();

    for (size_t i = 0; i < n_digits; i++) {
        int ai = i - a_f_sh;
        if (ai >= 0 && ai < (int)a.size)
            out[i] = a.data[ai];
        else if (ai < 0)
            out[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
        else if (a.sign)
            out[i] = last_a;
        else
            out[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    return out;
}

CFHE_FixedPoint::CFHE_FixedPoint(size_t n_digits, size_t n_frac, bool is_signed)
    : CFHE_Integer(n_digits, is_signed) {
    frac_size = n_frac < n_digits ? n_frac : n_digits;
}

CFHE_FixedPoint::CFHE_FixedPoint(double d, size_t n_digits, size_t n_frac,
                                 bool is_signed)
    : CFHE_Integer(n_digits, is_signed) {
    frac_size = n_frac < n_digits ? n_frac : n_digits;
    data = double2fp(d, n_digits, frac_size);
}

CFHE_FixedPoint::CFHE_FixedPoint(const FixedPoint &fp, size_t n_frac,
                                 bool is_signed)
    : CFHE_Integer(fp, is_signed) {
    frac_size = n_frac < fp.size() ? n_frac : fp.size();
}

CFHE_FixedPoint::CFHE_FixedPoint(const CFHE_FixedPoint &other)
    : CFHE_Integer(other) {
    frac_size = other.frac_size;
}

CFHE_FixedPoint::CFHE_FixedPoint(const CFHE_Integer &other)
    : CFHE_Integer(other) {
    frac_size = 0;
}

size_t CFHE_FixedPoint::getFracSize() const { return frac_size; }

void CFHE_FixedPoint::setFracSize(size_t n_frac) {
    frac_size = n_frac < size ? n_frac : size;
}

const CFHE_Integer
CFHE_FixedPoint::operator==(const CFHE_FixedPoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp({cfhe_base->GetArithmeticsEngine()->CmpEq(a, b)});
    return CFHE_Integer(fp, false);
}

const CFHE_FixedPoint
CFHE_FixedPoint::operator+(const CFHE_FixedPoint &other) const {
    FixedPoint a, b;
    size_t n_digits, n_frac;
    bool sign;
    promote(*this, other, a, b, n_digits, n_frac, sign);
    FixedPoint fp(cfhe_base->GetArithmeticsEngine()->AddNC(a, b));
    return CFHE_FixedPoint(fp, n_frac, sign);
}

const CFHE_FixedPoint
CFHE_FixedPoint::operator+=(const CFHE_FixedPoint &other) {
    _sync_var();
    FixedPoint o = promote(other, size, frac_size);
    data = cfhe_base->GetArithmeticsEngine()->AddNC(data, o);
    _sync_var();
    return *this;
}

const CFHE_FixedPoint CFHE_FixedPoint::operator+(double other) const {
    return *this + CFHE_FixedPoint(other, size, frac_size, sign);
}

const CFHE_FixedPoint CFHE_FixedPoint::operator+=(double other) {
    return *this += CFHE_FixedPoint(other, size, frac_size, sign);
}

CFHE_FixedPoint::operator double() const {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    if (sign) {
        return (double)CFHE_Integer::sign_extend(
                   cfhe_base->DecryptInt(data, size), size) /
               (1 << frac_size);
    } else {
        return (double)cfhe_base->DecryptInt(data, size) / (1 << frac_size);
    }
}

ostream &computefhe::operator<<(ostream &out, const CFHE_FixedPoint &obj) {
    // Client-mode only
    if (!CLIENT_MODE)
        OPENFHE_THROW("Not allowed in server mode.");

    if (obj.sign) {
        out << (double)CFHE_Integer::sign_extend(
                   cfhe_base->DecryptInt(obj.data, obj.size), obj.size) /
                   (1 << obj.frac_size);
    } else {
        out << (double)cfhe_base->DecryptInt(obj.data, obj.size) /
                   (1 << obj.frac_size);
    }
    return out;
}