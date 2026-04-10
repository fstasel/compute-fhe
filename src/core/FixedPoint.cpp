#include <computefhe/FixedPoint.h>

using namespace lbcrypto;
using namespace std;
using namespace computefhe;

BinaryDigit::BinaryDigit() { p = 0; }

BinaryDigit::BinaryDigit(const BinaryDigit &other) {
    c = other.c ? COPY_CT(other.c) : nullptr;
    p = other.p;
}

BinaryDigit::BinaryDigit(ConstLWECiphertext &ct) {
    c = ct ? COPY_CT(ct) : nullptr;
    p = 0;
}

BinaryDigit::BinaryDigit(const LWECiphertext &ct) {
    c = ct ? COPY_CT(ct) : nullptr;
    p = 0;
}

BinaryDigit::BinaryDigit(LWEPlaintext pt) {
    p = pt;
    c = nullptr;
}

BinaryDigit::BinaryDigit(const ConstLWECiphertext &ct, LWEPlaintext pt) {
    c = ct ? COPY_CT(ct) : nullptr;
    p = pt;
}

BinaryDigit &BinaryDigit::operator=(const BinaryDigit &other) {
    if (this != &other) {
        c = other.c ? COPY_CT(other.c) : nullptr;
        p = other.p;
    }
    return *this;
}

BinaryDigit &BinaryDigit::operator=(const LWECiphertext &other) {
    c = other ? COPY_CT(other) : nullptr;
    p = 0;
    return *this;
}

BinaryDigit &BinaryDigit::operator=(LWEPlaintext pt) {
    p = pt;
    c = nullptr;
    return *this;
}

BinaryDigit::operator LWECiphertext &() { return c; }

BinaryDigit::operator const LWECiphertext &() const { return c; }

BinaryDigit::operator ConstLWECiphertext() const { return c; }

BinaryDigit::operator LWEPlaintext() const { return p; }

FixedPoint::FixedPoint() : vector<BinaryDigit>() {}

FixedPoint::FixedPoint(size_t n) : vector<BinaryDigit>(n) {}

FixedPoint::FixedPoint(vector<BinaryDigit>::const_iterator begin,
                       vector<BinaryDigit>::const_iterator end)
    : vector<BinaryDigit>(begin, end) {}

FixedPoint::FixedPoint(const vector<BinaryDigit> &other)
    : vector<BinaryDigit>(other) {}

FixedPoint::FixedPoint(initializer_list<BinaryDigit> list)
    : vector<BinaryDigit>(list) {}

FixedPoint::FixedPoint(const vector<LWECiphertext> &other)
    : vector<BinaryDigit>(other.size()) {
    for (size_t i = 0; i < other.size(); i++) {
        (*this)[i] = other[i];
    }
}

FixedPoint::FixedPoint(const vector<LWEPlaintext> &other)
    : vector<BinaryDigit>(other.size()) {
    for (size_t i = 0; i < other.size(); i++) {
        (*this)[i] = other[i];
    }
}
