#include <computefhe/CFHE_Integer.h>
#include <computefhe/ComputeFHE.h>

using namespace computefhe;
using namespace std;

void test_eint() {
    Ebool::Init(CCPARAM_TOY, AE_OPTIMIZED);

    Ebool a = true;
    Eint8 b = -1;
    Euint8 c = -1;
    Eint16 d = -1;
    Euint16 e = -1;
    Eint32 f = -1;
    Euint32 g = -1;
    Eint64 h = -1;
    Euint64 i = -1;
    Eint8 j = -1;
    Ebool k = (e == b);

    cout << "a: " << a << endl
         << "b: " << b << endl
         << "c: " << c << endl
         << "d: " << d << endl
         << "e: " << e << endl
         << "f: " << f << endl
         << "g: " << g << endl
         << "h: " << h << endl
         << "i: " << i << endl
         << "j: " << j << endl
         << "k: " << k << endl;
}

int main() {
    test_eint();
    return 0;
}
