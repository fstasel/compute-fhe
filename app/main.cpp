#include <computefhe/CFHE_Integer.h>
#include <computefhe/ComputeFHE.h>

using namespace computefhe;
using namespace std;

void test_arithmetic_operators() {
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

void test_logic_operators() {
    Euint16 x = 0x1111;
    Euint16 y = 0x3333;

    cout << "&: " << (x & y) << endl;
    cout << "|: " << (x | y) << endl;
    cout << "^: " << (x ^ y) << endl;
    cout << "& 0x00FF: " << (x & 0x00FF) << endl;
    cout << "| 0x00FF: " << (x | 0x00FF) << endl;
    cout << "ˆ 0x00FF: " << (x ^ 0x00FF) << endl;
}

void test_shift_operators() {
    for (int i = 0; i < 20; i++) {
        Euint16 x = 50;
        Euint16 y = 50;
        Eint16 z = -50;
        Eint16 t = -50;
        uint16_t xx = 50;
        uint16_t yy = 50;
        int16_t zz = -50;
        int16_t tt = -50;
        x = x << i;
        y = y >> i;
        z = z << i;
        t = t >> i;
        xx = xx << i;
        yy = yy >> i;
        zz = zz << i;
        tt = tt >> i;
        cout << "i = " << i << endl
             << "  x = " << x << " --- " << xx << endl
             << "  y = " << y << " --- " << yy << endl
             << "  z = " << z << " --- " << zz << endl
             << "  t = " << t << " --- " << tt << endl;
    }
}

int main() {
    computefhe::Init(CCPARAM_TOY, AE_OPTIMIZED);
    // test_arithmetic_operators();
    // test_logic_operators();
    test_shift_operators();
    return 0;
}
