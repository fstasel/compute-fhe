#pragma once

#include <vector>

namespace computefhe {

    template <class T> class Evector : public std::vector<T> {
      public:
        using std::vector<T>::vector;
        using std::vector<T>::operator[];
        template <class U, bool S>
        T &operator[](const CFHE_Integer<U, S> &index);
        template <class U, bool S>
        const T &operator[](const CFHE_Integer<U, S> &index) const;
    };

} // namespace computefhe
