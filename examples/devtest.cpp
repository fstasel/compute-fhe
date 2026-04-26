#include <computefhe/ComputeFHE.h>

using namespace computefhe;
using namespace std;

void test_arithmetic_operators() {
    Eint32 a = -20000;
    Eint32 b = 65537;
    Eint16 c = b;
    Eint16 d = c + 1000;
    Eint16 e = c - d;
    Eint16 f = c + (Eint8)d;

    cout << "a: " << a << endl
         << "b: " << b << endl
         << "c: " << c << endl
         << "d: " << d << endl
         << "e: " << e << endl
         << "f: " << f << endl;
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
    cout << "x ^ 0x00FF: " << (x ^ 0x00FF) << "  Expected: " << (xx ^ 0x00FF)
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
    cout << "x ^= 0x00FF: " << (x ^= 0x00FF) << "  Expected: " << (xx ^= 0x00FF)
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

void test_condition() {
    Eint16 x = 10;
    Eint16 y = 20;
    Eint16 z = 30;

    cout << "Before condition: x = " << x << ", y = " << y << ", z = " << z
         << endl;

    Eif(Ebool(true)) {
        Eif(Ebool(false)) { x = y; }
        else {
            x = 0;
        }
    }
    else Eif(Ebool(false)) {
        y = z;
    }
    else {
        z = x;
    }

    cout << "After condition: x = " << x << ", y = " << y << ", z = " << z
         << endl;
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

void test_vector() {
    Evector<Eint16> vec(8);
    Euint8 d = 3, e = 1;
    vec[0] = Eint16(10);
    vec[1] = 20;
    vec[2] = vec[0] + vec[e];
    vec[d] = vec[e] + vec[0];
    vec[4] = vec[d] + 5;
    vec[5] = vec[d] | vec[e];
    vec[6] = 60;
    vec[6] += vec[5];
    vec[d] = -vec[d];
    vec[e] <<= 1;
    vec[d]++;

    cout << "vec[0]: " << vec[0] << endl;
    cout << "vec[1]: " << vec[1] << endl;
    cout << "vec[2]: " << vec[2] << endl;
    cout << "vec[d]: " << vec[d] << endl;
    cout << "vec[4]: " << vec[4] << endl;
    cout << "vec[5]: " << vec[5] << endl;
    cout << "vec[6]: " << vec[6] << endl;
    cout << "vec[7]: " << vec[7] << endl;
    cout << "vec[d] < vec[4]: " << (vec[d] < vec[4]) << endl;
    cout << "-vec[d]: " << -vec[d] << endl;
}

void test_vector_custom() {
    using MyEint = EInt<int16_t, 6, true>;
    using MyEuint = EInt<uint8_t, 3, false>;

    MyEuint d = 3, e = 1;
    cout << "d: " << d << ", e: " << e << endl;
    MyEint k = 10;
    cout << "k: " << k << endl;
    cout << "d + 1: " << d + 1 << endl;
    cout << "k + 1: " << k + 1 << endl;

    Evector<MyEint> vec(8);
    vec[0] = MyEint(10);
    vec[1] = 20;
    vec[2] = vec[0] + vec[e];
    vec[d] = vec[e] + vec[0];
    vec[4] = vec[d] - 1;
    vec[5] = vec[d] | vec[2];
    vec[6] = 60;
    vec[6] += vec[5];
    vec[d] = -vec[d];
    vec[e] <<= 1;
    vec[d]++;

    cout << "vec[0]: " << vec[0] << endl;
    cout << "vec[1]: " << vec[1] << endl;
    cout << "vec[2]: " << vec[2] << endl;
    cout << "vec[d]: " << vec[d] << endl;
    cout << "vec[4]: " << vec[4] << endl;
    cout << "vec[5]: " << vec[5] << endl;
    cout << "vec[6]: " << vec[6] << endl;
    cout << "vec[7]: " << vec[7] << endl;
    cout << "vec[d] < vec[4]: " << (vec[d] < vec[4]) << endl;
    cout << "-vec[d]: " << -vec[d] << endl;
}

void test_fp() {
    Efixedpoint a(-7.9, 8, 4, true);
    Efixedpoint b(1.5, 8, 4, true);
    Efixedpoint c(1.25, 4, 2, true);
    cout << "a: " << a << endl;
    cout << "b: " << b << endl;
    cout << "c: " << c << endl;
    cout << "a + c: " << a + c << endl;
    a += b;
    cout << "a += b: " << a << endl;
    a += c;
    cout << "a += c: " << a << endl;
    cout << "b == c: " << (b == c) << endl;
    a += 1.25;
    cout << "a += 1.25: " << a << endl;
    double d = (double)a;
    cout << "double d = a: " << d << endl;
    Eint16 k = a.toInteger();
    cout << "Eint16 k = a: " << k << endl;
    a = -5.7;
    cout << "a = -5.7: " << a << endl;
    a = c;
    cout << "a = c: " << a << endl;
    cout << "a: " << a << ", b: " << b << ", c: " << c << endl;
    a -= b;
    cout << "a -= b: " << a << endl;
    a -= 1.75;
    cout << "a -= 1.75: " << a << endl;

    cout << "a: " << a << ", b: " << b << endl;
    if (c == b)
        cout << "c == b" << endl;
    if (c != b)
        cout << "c != b" << endl;
    if (c >= b)
        cout << "c >= b" << endl;
    if (c <= b)
        cout << "c <= b" << endl;
    if (c < b)
        cout << "c < b" << endl;
    if (c > b)
        cout << "c > b" << endl;

    if (a == -6.875)
        cout << "a == -6.875" << endl;
    if (a != -6.875)
        cout << "a != -6.875" << endl;
    if (a >= -6.875)
        cout << "a >= -6.875" << endl;
    if (a <= -6.875)
        cout << "a <= -6.875" << endl;
    if (a < -6.875)
        cout << "a < -6.875" << endl;
    if (a > -6.875)
        cout << "a > -6.875" << endl;
    cout << "-a: " << -a << endl;
    a <<= 1;
    cout << "a <<= 1: " << a << endl;
    Efixedpoint p = a * b;
    cout << "p = a * b: " << p << endl;
    Efixedpoint q = a * c;
    cout << "q = a * c: " << q << endl;
    Efixedpoint t = a;
    a *= b;
    cout << "a *= b: " << a << endl;
    a = t;
    a *= c;
    cout << "a *= c: " << a << endl;
    p = a * -0.5;
    cout << "p = a * -0.5: " << p << endl;
    q = a * 0.25;
    cout << "q = a * 0.25: " << q << endl;
    a *= -0.5;
    cout << "a *= -0.5: " << a << endl;
    a++;
    cout << "a++: " << a << endl;
}

void test_fp_vector() {
    Evector<Efixedpoint> vec(4);
    vec[0] = Efixedpoint(1.5, 4, 2, true);
    vec[1] = Efixedpoint(-2.25, 8, 4, true);
    vec[2] = vec[0] + vec[1];
    vec[3] = vec[0] * vec[1];

    Euint8 idx = 2;
    cout << "vec[0]: " << vec[0] << endl;
    cout << "vec[1]: " << vec[1] << endl;
    cout << "vec[idx]: " << vec[idx] << endl;
    cout << "vec[3]: " << vec[3] << endl;
    cout << "vec[0] << 1: " << (vec[0] << 1) << endl;
    cout << "++vec[0]: " << (++vec[0]) << endl;
    vec[0] >>= 1;
    cout << "vec[0] >>= 1: " << vec[0] << endl;
    vec[idx] *= -1.5;
    cout << "vec[idx] *= -1.5: " << vec[idx] << endl;
    cout << "-vec[idx]: " << -vec[idx] << endl;
    cout << "++vec[idx]: " << (++vec[idx]) << endl;
}

void test_fp_custom() {
    using MyEfix = EFix<7, 4, true>;
    MyEfix a = 1.5;
    cout << "a: " << a << endl;
    MyEfix b = -2.25;
    cout << "b: " << b << endl;
    MyEfix c = a + b;
    cout << "c = a + b: " << c << endl;

    Evector<MyEfix> vec(4);
    vec[0] = 1.5;
    vec[1] = -2.25;
    vec[2] = vec[0] + vec[1];
    vec[3] = vec[0] * vec[1];

    Euint8 idx = 2;
    cout << "vec[0]: " << vec[0] << endl;
    cout << "vec[1]: " << vec[1] << endl;
    cout << "vec[idx]: " << vec[idx] << endl;
    cout << "vec[3]: " << vec[3] << endl;
    cout << "vec[0] << 1: " << (vec[0] << 1) << endl;
    cout << "++vec[0]: " << (++vec[0]) << endl;
    vec[0] >>= 1;
    cout << "vec[0] >>= 1: " << vec[0] << endl;
    vec[idx] *= -1.5;
    cout << "vec[idx] *= -1.5: " << vec[idx] << endl;
    cout << "-vec[idx]: " << -vec[idx] << endl;
    cout << "++vec[idx]: " << (++vec[idx]) << endl;
}

void test_simulation() {
    BaseALUSimulator *s = cfhe_base->GetSimulator();
    if (!s) {
        cout << "Not in simulation mode!" << endl;
        return;
    }
    s->ResetStats();
    Euint8 a = 10;
    Euint8 b = 10;
    cout << "a * b: " << a * b << endl;
    s->PrintStats();
    s->ResetStats();
    Eif(a < b) { a = 20; }
    else {
        b = 20;
    }
    cout << "a: " << a << ", b: " << b << endl;
    s->PrintStats();
    s->ResetStats();
    Evector<Euint8> vec(4);
    vec[0] = 10;
    vec[1] = 20;
    vec[2] = 30;
    vec[3] = 40;
    a = 3;
    cout << "vec[a]: " << vec[a] << endl;
    s->PrintStats();
    s->ResetStats();
    vec[a] = 100;
    cout << "vec[3]: " << vec[3] << endl;
    s->PrintStats();
}

void test_div() {
    Euint8 a = 100;
    Euint8 b = 40;
    cout << "a / b: " << a / b << endl;
    cout << "a %= b: " << (a %= b) << endl;
    cout << "a / 3: " << a / 3 << endl;
    cout << "a %= 3: " << (a %= 3) << endl;
    cout << "50 / b: " << 50 / b << endl;
    cout << "50 % b: " << 50 % b << endl;

    using MyEfix = EFix<15, 7, false>;
    MyEfix c = 10.5;
    MyEfix d = 4.2;
    cout << "c / d: " << c / d << endl;
    cout << "c /= d: " << (c /= d) << endl;
    cout << "c / 0.5: " << c / 0.5 << endl;
    cout << "11.25 / c: " << 11.25 / c << endl;

    Evector<Euint8> vec(4);
    Euint8 idx = 0;
    vec[0] = 100;
    vec[1] = 40;
    vec[2] = vec[idx] / vec[1];
    cout << "vec[2]: " << vec[2] << endl;
    vec[3] = vec[idx] % vec[1];
    cout << "vec[3]: " << vec[3] << endl;
    cout << "vec[3] / 3: " << vec[3] / 3 << endl;
    cout << "vec[3] % 3: " << vec[3] % 3 << endl;
    vec[idx] %= vec[1];
    cout << "vec[idx] %= vec[1]: " << vec[idx] << endl;
    vec[idx] /= 5;
    cout << "vec[idx] /= 5: " << vec[idx] << endl;
}

void test_auto_enc() {
    BaseALUSimulator *s = cfhe_base->GetSimulator();
    if (s) {
        s->ResetStats();
    }

    Eint32 x = 100;
    cout << "x*x: " << x * x << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cfhe_base->setAutoEncryptMode(false);

    Eint32 y = 100;

    cout << "y*y: " << y * y << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "x*y: " << x * y << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }
}

void test_plaintext() {
    BaseALUSimulator *s = cfhe_base->GetSimulator();
    if (s) {
        s->ResetStats();
    }

    Eint32 a = 1000000;
    Eint32 b = (1 << 10);
    cout << "a: " << a << ", b: " << b << endl;
    cout << "a + b: " << a + b << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "a + (1<<10): " << a + (1 << 10) << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "b - 512: " << b - 512 << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }
    cfhe_base->setAutoEncryptMode(false);
    cout << "512 - b: " << (Eint32)512 - b << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "b > (1<<25)-1: " << (b > (1 << 25) - 1) << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "b >= (1<<25)-1: " << (b >= (1 << 25) - 1) << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "b < (1<<25)-1: " << (b < (1 << 25) - 1) << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "b <= (1<<25)-1: " << (b <= (1 << 25) - 1) << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "b == (1<<25)-1: " << (b == (1 << 25) - 1) << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "b != (1<<25)-1: " << (b != (1 << 25) - 1) << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cfhe_base->setAutoEncryptMode(true);
    Efixedpoint f(-2.25, 8, 4, true);
    cout << "f: " << f << endl;
    cout << "f + 1.5: " << f + 1.5 << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cout << "f / 0.5: " << f / 0.5 << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }

    cfhe_base->setAutoEncryptMode(true);
    Eint32 ct = 15;
    cfhe_base->setAutoEncryptMode(false);
    Eint32 pt = 17;
    cout << "ct: " << ct << ", pt: " << pt << endl;
    cout << "ct * pt: " << ct * pt << endl;

    if (s) {
        s->PrintStats();
        s->ResetStats();
    }
}

void test_friend_functions() {
    Eint32 a = 7, b = -7;
    Eint32 c = false, d = true;

    cout << "a    : 7" << endl;
    cout << "b    : -7" << endl;
    cout << "3+a  : " << 3 + a << endl;
    cout << "15-a : " << 15 - a << endl;
    cout << "4-a  : " << 4 - a << endl;
    cout << "15-b : " << 15 - b << endl;
    cout << "3*a  : " << 3 * a << endl;
    cout << "22/a : " << 22 / a << endl;
    cout << "22%a : " << 22 % a << endl << endl;

    cout << "7==a : " << (7 == a) << endl;
    cout << "7!=a : " << (7 != a) << endl;
    cout << "7<a  : " << (7 < a) << endl;
    cout << "7<=a : " << (7 <= a) << endl;
    cout << "7>a  : " << (7 > a) << endl;
    cout << "7>=a : " << (7 >= a) << endl;
    cout << "-7==a: " << (-7 == a) << endl;
    cout << "-7!=a: " << (-7 != a) << endl;
    cout << "-7<a : " << (-7 < a) << endl;
    cout << "-7<=a: " << (-7 <= a) << endl;
    cout << "-7>a : " << (-7 > a) << endl;
    cout << "-7>=a: " << (-7 >= a) << endl << endl;

    cout << "7==b : " << (7 == b) << endl;
    cout << "7!=b : " << (7 != b) << endl;
    cout << "7<b  : " << (7 < b) << endl;
    cout << "7<=b : " << (7 <= b) << endl;
    cout << "7>b  : " << (7 > b) << endl;
    cout << "7>=b : " << (7 >= b) << endl;
    cout << "-7==b: " << (-7 == b) << endl;
    cout << "-7!=b: " << (-7 != b) << endl;
    cout << "-7<b : " << (-7 < b) << endl;
    cout << "-7<=b: " << (-7 <= b) << endl;
    cout << "-7>b : " << (-7 > b) << endl;
    cout << "-7>=b: " << (-7 >= b) << endl << endl;

    cout << "10&a : " << (10 & a) << endl;
    cout << "8|a  : " << (8 | a) << endl;
    cout << "10^a : " << (10 ^ a) << endl << endl;

    cout << "0  && c : " << (0 && c) << endl;
    cout << "0  && d : " << (0 && d) << endl;
    cout << "10 && c : " << (10 && c) << endl;
    cout << "10 && d : " << (10 && d) << endl << endl;

    cout << "0  || c : " << (0 || c) << endl;
    cout << "0  || d : " << (0 || d) << endl;
    cout << "10 || c : " << (10 || c) << endl;
    cout << "10 || d : " << (10 || d) << endl;
}

int main() {
    computefhe::Init(CCPARAM_TOY, ALU_STANDARD, true, true);

    // test_arithmetic_operators();
    // test_arithmetic_assignment_operators();
    // test_comparison_operators();
    // test_logic_operators();
    // test_logic_assignment_operators();
    // test_shift_operators();
    // test_shift_assign_operators();
    // test_condition();
    // test_inc_dec();
    // test_vector();
    // test_vector_custom();
    // test_fp();
    // test_fp_vector();
    // test_fp_custom();
    // test_div();
    // test_simulation();
    // test_auto_enc();
    test_plaintext();
    // test_friend_functions();

    computefhe::Finalize();

    return 0;
}
