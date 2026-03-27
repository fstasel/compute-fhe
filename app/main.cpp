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

void test_comparison_operators() {
    Eint16 x = -3;
    Eint16 y = 10;
    cout << "x: " << x << ", y: " << y << endl;
    cout << "x == y: " << (x == y) << endl;
    cout << "x != y: " << (x != y) << endl;
    cout << "x > y: " << (x > y) << endl;
    cout << "x >= y: " << (x >= y) << endl;
    cout << "x < y: " << (x < y) << endl;
    cout << "x <= y: " << (x <= y) << endl;
    cout << "x == 10: " << (x == 10) << endl;
    cout << "x != 10: " << (x != 10) << endl;
    cout << "x > 10: " << (x > 10) << endl;
    cout << "x >= 10: " << (x >= 10) << endl;
    cout << "x < 10: " << (x < 10) << endl;
    cout << "x <= 10: " << (x <= 10) << endl;
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

    Ebool a = true;
    Eint32 b = 0;
    cout << "a: " << a << ", b: " << b << endl;
    cout << "a && b: " << (a && b) << endl;
    cout << "a && 100: " << (a && 100) << endl;
    cout << "a && 0: " << (a && 0) << endl;
    cout << "a || b: " << (a || b) << endl;
    cout << "b || 100: " << (b || 100) << endl;
    cout << "b || 0: " << (b || 0) << endl;
    cout << "!a: " << (!a) << endl;
    cout << "~a: " << (~a) << endl;
    cout << "!b: " << (!b) << endl;
    cout << "~b: " << (~b) << endl;
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

void test_inc_dec() {
    Euint8 a = 0;
    Euint16 b = 0;
    Euint32 c = 0;
    Euint64 d = 0;
    Eint8 e = 0;
    Eint16 f = 0;
    Eint32 g = 0;
    Eint64 h = 0;

    cout << "---Euint8---" << endl;
    cout << "[a <- 0]" << endl;
    cout << " a++: " << (uint)(a++) << endl;
    cout << " a  : " << (uint)(a) << endl;
    cout << " ++a: " << (uint)(++a) << endl;
    cout << " a  : " << (uint)(a) << endl << endl;
    a = 0;
    cout << "[a <- 0]" << endl;
    cout << " a--: " << (uint)(a--) << endl;
    cout << " a  : " << (uint)(a) << endl;
    cout << " --a: " << (uint)(--a) << endl;
    cout << " a  : " << (uint)(a) << endl << endl;

    cout << "---Euint16---" << endl;
    cout << "[b <- 0]" << endl;
    cout << " b++: " << b++ << endl;
    cout << " b  : " << b << endl;
    cout << " ++b: " << ++b << endl;
    cout << " b  : " << b << endl << endl;
    b = 0;
    cout << "[b <- 0]" << endl;
    cout << " b--: " << b-- << endl;
    cout << " b  : " << b << endl;
    cout << " --b: " << --b << endl;
    cout << " b  : " << b << endl << endl;

    cout << "---Euint32---" << endl;
    cout << "[c <- 0]" << endl;
    cout << " c++: " << c++ << endl;
    cout << " c  : " << c << endl;
    cout << " ++c: " << ++c << endl;
    cout << " c  : " << c << endl << endl;
    c = 0;
    cout << "[c <- 0]" << endl;
    cout << " c--: " << c-- << endl;
    cout << " c  : " << c << endl;
    cout << " --c: " << --c << endl;
    cout << " c  : " << c << endl << endl;

    cout << "---Euint64---" << endl;
    cout << "[d <- 0]" << endl;
    cout << " d++: " << d++ << endl;
    cout << " d  : " << d << endl;
    cout << " ++d: " << ++d << endl;
    cout << " d  : " << d << endl << endl;
    d = 0;
    cout << "[d <- 0]" << endl;
    cout << " d--: " << d-- << endl;
    cout << " d  : " << d << endl;
    cout << " --d: " << --d << endl;
    cout << " d  : " << d << endl << endl;

    cout << "---Eint8---" << endl;
    cout << "[e <- 0]" << endl;
    cout << " e++: " << (int)(e++) << endl;
    cout << " e  : " << (int)(e) << endl;
    cout << " ++e: " << (int)(++e) << endl;
    cout << " e  : " << (int)(e) << endl << endl;
    e = 0;
    cout << "[e <- 0]" << endl;
    cout << " e--: " << (int)(e--) << endl;
    cout << " e  : " << (int)(e) << endl;
    cout << " --e: " << (int)(--e) << endl;
    cout << " e  : " << (int)(e) << endl << endl;

    cout << "---Eint16---" << endl;
    cout << "[f <- 0]" << endl;
    cout << " f++: " << f++ << endl;
    cout << " f  : " << f << endl;
    cout << " ++f: " << ++f << endl;
    cout << " f  : " << f << endl << endl;
    f = 0;
    cout << "[f <- 0]" << endl;
    cout << " f--: " << f-- << endl;
    cout << " f  : " << f << endl;
    cout << " --f: " << --f << endl;
    cout << " f  : " << f << endl << endl;

    cout << "---Eint32---" << endl;
    cout << "[g <- 0]" << endl;
    cout << " g++: " << g++ << endl;
    cout << " g  : " << g << endl;
    cout << " ++g: " << ++g << endl;
    cout << " g  : " << g << endl << endl;
    g = 0;
    cout << "[g <- 0]" << endl;
    cout << " g--: " << g-- << endl;
    cout << " g  : " << g << endl;
    cout << " --g: " << --g << endl;
    cout << " g  : " << g << endl << endl;

    cout << "---Eint64---" << endl;
    cout << "[h <- 0]" << endl;
    cout << " h++: " << h++ << endl;
    cout << " h  : " << h << endl;
    cout << " ++h: " << ++h << endl;
    cout << " h  : " << h << endl << endl;
    h = 0;
    cout << "[h <- 0]" << endl;
    cout << " h--: " << h-- << endl;
    cout << " h  : " << h << endl;
    cout << " --h: " << --h << endl;
    cout << " h  : " << h << endl;
}

int main() {
    computefhe::Init(CCPARAM_TOY, AE_OPTIMIZED);

    // test_arithmetic_operators();
    // test_arithmetic_assignment_operators();
    // test_comparison_operators();
    // test_logic_operators();
    // test_logic_assignment_operators();
    // test_shift_operators();
    // test_shift_assign_operators();
    test_inc_dec();

    return 0;
}
