#include <computefhe/CFHE_int.h>
#define DSIZE 32

computefhe::CFHE_int::CFHE_int() : CFHE_Integer() {
    data = cfhe->GetConstantInt(0, DSIZE);
    size = DSIZE;
}

computefhe::CFHE_int::CFHE_int(int d) : CFHE_Integer(d, DSIZE) {
    // empty
}
