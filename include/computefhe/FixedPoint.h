#pragma once
#include <openfhe/binfhe/binfhecontext.h>
#include <vector>

using namespace lbcrypto;
using namespace std;

#define COPY_CT(x) std::make_shared<LWECiphertextImpl>(*x)

namespace computefhe {

    struct BinaryDigit {
        static uint new_id;
        uint id = 0;
        LWECiphertext c;
        LWEPlaintext p;
        bool is_ct;
        BinaryDigit();
        BinaryDigit(const BinaryDigit &other);
        BinaryDigit(ConstLWECiphertext &ct);
        BinaryDigit(const LWECiphertext &ct);
        BinaryDigit(LWEPlaintext pt);
        BinaryDigit(const ConstLWECiphertext &ct, LWEPlaintext pt,
                    bool is_ct = false);
        BinaryDigit &operator=(const BinaryDigit &other);
        BinaryDigit &operator=(const LWECiphertext &other);
        BinaryDigit &operator=(LWEPlaintext pt);
        bool operator==(const BinaryDigit &other) const;
        bool operator!=(const BinaryDigit &other) const;
        operator LWECiphertext &();
        operator const LWECiphertext &() const;
        operator ConstLWECiphertext() const;
        operator LWEPlaintext() const;
    };
    struct FixedPoint : public vector<BinaryDigit> {
        FixedPoint();
        FixedPoint(size_t n);
        FixedPoint(vector<BinaryDigit>::const_iterator begin,
                   vector<BinaryDigit>::const_iterator end);
        FixedPoint(std::initializer_list<BinaryDigit> list);
        FixedPoint(const vector<BinaryDigit> &other);
        FixedPoint(const vector<LWECiphertext> &other);
        FixedPoint(const vector<LWEPlaintext> &other);
    };
} // namespace computefhe