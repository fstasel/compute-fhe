#pragma once

#include <computefhe/CFHE_Integer.h>
#include <computefhe/ComputeFHE.h>
#include <vector>

namespace computefhe {

    template <typename T> class Evector;

    class Eitem {
      protected:
        Evector<CFHE_Integer> &data;
        FixedPoint index;
        size_t p_index;
        bool encrypted_index;

      public:
        Eitem(Evector<CFHE_Integer> &vec, const CFHE_Integer &idx);
        Eitem(Evector<CFHE_Integer> &vec, const size_t idx);
        operator CFHE_Integer() const;
        const CFHE_Integer &operator=(const CFHE_Integer &value);

        CFHE_Integer operator+(const CFHE_Integer &b) const;
        CFHE_Integer operator+(uint64_t b) const;
        CFHE_Integer operator-(const CFHE_Integer &b) const;
        CFHE_Integer operator-(uint64_t b) const;
        CFHE_Integer operator*(const CFHE_Integer &b) const;
        CFHE_Integer operator*(uint64_t b) const;
        CFHE_Integer operator&(const CFHE_Integer &b) const;
        CFHE_Integer operator&(uint64_t b) const;
        CFHE_Integer operator|(const CFHE_Integer &b) const;
        CFHE_Integer operator|(uint64_t b) const;
        CFHE_Integer operator^(const CFHE_Integer &b) const;
        CFHE_Integer operator^(uint64_t b) const;

        CFHE_Integer operator==(const CFHE_Integer &b) const;
        CFHE_Integer operator==(uint64_t b) const;
        CFHE_Integer operator!=(const CFHE_Integer &b) const;
        CFHE_Integer operator!=(uint64_t b) const;
        CFHE_Integer operator>(const CFHE_Integer &b) const;
        CFHE_Integer operator>(uint64_t b) const;
        CFHE_Integer operator>=(const CFHE_Integer &b) const;
        CFHE_Integer operator>=(uint64_t b) const;
        CFHE_Integer operator<(const CFHE_Integer &b) const;
        CFHE_Integer operator<(uint64_t b) const;
        CFHE_Integer operator<=(const CFHE_Integer &b) const;
        CFHE_Integer operator<=(uint64_t b) const;

        CFHE_Integer operator&&(const CFHE_Integer &b) const;
        CFHE_Integer operator&&(uint64_t b) const;
        CFHE_Integer operator||(const CFHE_Integer &b) const;
        CFHE_Integer operator||(uint64_t b) const;

        CFHE_Integer operator<<(int b) const;
        CFHE_Integer operator>>(int b) const;

        Eitem &operator+=(const CFHE_Integer &b);
        Eitem &operator+=(uint64_t b);
        Eitem &operator-=(const CFHE_Integer &b);
        Eitem &operator-=(uint64_t b);
        Eitem &operator*=(const CFHE_Integer &b);
        Eitem &operator*=(uint64_t b);
        Eitem &operator&=(const CFHE_Integer &b);
        Eitem &operator&=(uint64_t b);
        Eitem &operator|=(const CFHE_Integer &b);
        Eitem &operator|=(uint64_t b);
        Eitem &operator^=(const CFHE_Integer &b);
        Eitem &operator^=(uint64_t b);
        Eitem &operator<<=(int b);
        Eitem &operator>>=(int b);

        CFHE_Integer operator!() const;
        CFHE_Integer operator~() const;
        CFHE_Integer operator-() const;
        CFHE_Integer operator++();
        CFHE_Integer operator++(int);
        CFHE_Integer operator--();
        CFHE_Integer operator--(int);
    };

    template <typename T> class Evector : public std::vector<T> {
      public:
        using std::vector<T>::vector;
        using std::vector<T>::operator[];

        Eitem operator[](const CFHE_Integer &index) {
            return Eitem(reinterpret_cast<Evector<CFHE_Integer> &>(*this),
                         index);
            // TODO: Use below in client-mode only
            return Eitem(reinterpret_cast<Evector<CFHE_Integer> &>(*this),
                         (size_t)index);
        }

        CFHE_Integer &operator[](const int idx) { return this->at(idx); }
    };

} // namespace computefhe
