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

void test_arithmetic_assignment_operators() {
    Eint16 x = 10;
    Eint16 y = 3;
    cout << "(orig) x: " << x << ", y: " << y << endl;

    x += y;
    cout << "(x+=y) x: " << x << ", y: " << y << endl;

    y += 3;
    cout << "(y+=3) x: " << x << ", y: " << y << endl;

    x -= y;
    cout << "(x-=y) x: " << x << ", y: " << y << endl;

    x -= 5;
    cout << "(x-=5) x: " << x << ", y: " << y << endl;

    x *= y;
    cout << "(x*=y) x: " << x << ", y: " << y << endl;

    x *= 2;
    cout << "(x*=2) x: " << x << ", y: " << y << endl;
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

int main() {
    computefhe::Init(CCPARAM_TOY, AE_OPTIMIZED);

    // test_arithmetic_operators();
    test_arithmetic_assignment_operators();
    // test_logic_operators();

    return 0;
}
