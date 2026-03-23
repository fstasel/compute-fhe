#include <computefhe/CFHE_Integer.h>
#include <computefhe/ComputeFHE.h>

using namespace computefhe;
using namespace std;

void test_arithmetic_operators() {
    Eint32 a = -20000;
    Eint32 b = -30000;
    Eint16 c = a + 50000;

    cout << "a: " << a << endl << "b: " << b << endl << "c: " << c << endl;
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
    uint16_t xx = 0x1111;
    uint16_t yy = 0x3333;

    cout << "&: " << (x & y) << "  Expected: " << (xx & yy) << endl;
    cout << "|: " << (x | y) << "  Expected: " << (xx | yy) << endl;
    cout << "^: " << (x ^ y) << "  Expected: " << (xx ^ yy) << endl;
    cout << "x: " << x << endl;
    cout << "x & 0x00FF: " << (x & 0x00FF) << "  Expected: " << (xx & 0x00FF)
         << endl;
    cout << "x | 0x00FF: " << (x | 0x00FF) << "  Expected: " << (xx | 0x00FF)
         << endl;
    cout << "x ˆ 0x00FF: " << (x ^ 0x00FF) << "  Expected: " << (xx ^ 0x00FF)
         << endl;
}

void test_logic_assignment_operators() {
    Euint16 x = 0x1111;
    Euint16 y = 0x3333;
    uint16_t xx = 0x1111;
    uint16_t yy = 0x3333;

    cout << "&=: " << (x &= y) << "  Expected: " << (xx &= yy) << endl;
    x = 0x1111;
    xx = 0x1111;
    cout << "|=: " << (x |= y) << "  Expected: " << (xx |= yy) << endl;
    x = 0x1111;
    xx = 0x1111;
    cout << "^=: " << (x ^= y) << "  Expected: " << (xx ^= yy) << endl;
    x = 0x1111;
    xx = 0x1111;
    cout << "x: " << x << endl;
    cout << "x &= 0x00FF: " << (x &= 0x00FF) << "  Expected: " << (xx &= 0x00FF)
         << endl;
    x = 0x1111;
    xx = 0x1111;
    cout << "x |= 0x00FF: " << (x |= 0x00FF) << "  Expected: " << (xx |= 0x00FF)
         << endl;
    x = 0x1111;
    xx = 0x1111;
    cout << "x ˆ= 0x00FF: " << (x ^= 0x00FF) << "  Expected: " << (xx ^= 0x00FF)
         << endl;
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

void test_shift_assign_operators() {
    for (int i = 0; i < 20; i++) {
        Euint16 x = 50;
        Euint16 y = 50;
        Eint16 z = -50;
        Eint16 t = -50;
        uint16_t xx = 50;
        uint16_t yy = 50;
        int16_t zz = -50;
        int16_t tt = -50;
        x <<= i;
        y >>= i;
        z <<= i;
        t >>= i;
        xx <<= i;
        yy >>= i;
        zz <<= i;
        tt >>= i;
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
    // test_arithmetic_assignment_operators();
    test_logic_operators();
    test_logic_assignment_operators();
    // test_shift_operators();
    // test_shift_assign_operators();

    return 0;
}
