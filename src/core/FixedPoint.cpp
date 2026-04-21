#include <computefhe/FixedPoint.h>

using namespace lbcrypto;
using namespace std;
using namespace computefhe;

uint BinaryDigit::new_id = 0;

BinaryDigit::BinaryDigit() {
    p = 0;
    is_ct = false;
    id = new_id++;
}

BinaryDigit::BinaryDigit(const BinaryDigit &other) {
    c = other.c ? COPY_CT(other.c) : nullptr;
    p = other.p;
    is_ct = other.is_ct;
    id = other.id;
}

BinaryDigit::BinaryDigit(ConstLWECiphertext &ct) {
    c = ct ? COPY_CT(ct) : nullptr;
    p = 0;
    is_ct = true;
    id = new_id++;
}

BinaryDigit::BinaryDigit(const LWECiphertext &ct) {
    c = ct ? COPY_CT(ct) : nullptr;
    p = 0;
    is_ct = true;
    id = new_id++;
}

BinaryDigit::BinaryDigit(LWEPlaintext pt) {
    p = pt;
    c = nullptr;
    is_ct = false;
    id = new_id++;
}

BinaryDigit::BinaryDigit(const ConstLWECiphertext &ct, LWEPlaintext pt,
                         bool is_ct) {
    c = ct ? COPY_CT(ct) : nullptr;
    p = pt;
    this->is_ct = is_ct;
    id = new_id++;
}

BinaryDigit &BinaryDigit::operator=(const BinaryDigit &other) {
    if (this != &other) {
        c = other.c ? COPY_CT(other.c) : nullptr;
        p = other.p;
        is_ct = other.is_ct;
        id = other.id;
    }
    return *this;
}

BinaryDigit &BinaryDigit::operator=(const LWECiphertext &other) {
    c = other ? COPY_CT(other) : nullptr;
    p = 0;
    is_ct = true;
    id = new_id++;
    return *this;
}

BinaryDigit &BinaryDigit::operator=(LWEPlaintext pt) {
    p = pt;
    c = nullptr;
    is_ct = false;
    id = new_id++;
    return *this;
}

bool BinaryDigit::operator==(const BinaryDigit &other) const {
    return id == other.id;
}

bool BinaryDigit::operator!=(const BinaryDigit &other) const {
    return id != other.id;
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

bool FixedPoint::is_ct() const {
    for (size_t i = 0; i < size(); i++) {
        if (!(*this)[i].is_ct)
            return false;
    }
    return true;
}
