#pragma once
#include <computefhe/CFHE_Integer.h>

namespace computefhe {
    class CFHE_int : public CFHE_Integer {
        public:
            CFHE_int();
            CFHE_int(int d);
            using CFHE_Integer::operator=;
    };
}