#pragma once

#include <computefhe/CFHE_Integer.h>
#include <computefhe/ComputeFHE.h>
#include <vector>

namespace computefhe {

    template <class T> class Eitem;

    template <class T> class Evector : public std::vector<T> {
      public:
        using std::vector<T>::vector;
        using std::vector<T>::operator[];
        template <class I> Eitem<T> operator[](I &index);
    };

    template <class T> class Eitem {
      protected:
        Evector<T> &data;
        FixedPoint index;
        size_t p_index;
        bool encrypted_index;

      public:
        template <class I> Eitem(Evector<T> &vec, const I &idx);
        Eitem(Evector<T> &vec, const size_t idx);
        operator T();
        const T &operator=(const T &value);
    };

} // namespace computefhe
