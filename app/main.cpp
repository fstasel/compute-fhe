#include <computefhe/ComputeFHE.h>
#include <computefhe/CFHE_Integer.h>

using namespace computefhe;
using namespace std;

void test_eint() {
    Ebool a = true;
    Eint8 b = -10;
    Euint8 c = -10;
    Eint16 d= -1000;
    Euint16 e = -1000;
    Eint32 f = -1000000;
    Euint32 g = -1000000;
    Eint64 h = -1;
    Euint64 i = -1;
    Euint64 j = -1;

    cout << "a: " << a << endl
    << "b: " << b << endl
    << "c: " << c << endl
    << "d: " << d << endl
    << "e: " << e << endl
    << "f: " << f << endl
    << "g: " << g << endl
    << "h: " << h << endl
    << "i: " << i << endl
    << "j: " << j << endl;
}
    
int main() {
    test_eint();
    return 0;
}
