#include <computefhe/ComputeFHE.h>
#include <computefhe/CFHE_int.h>

using namespace computefhe;
using namespace std;

void test_eint() {
    CFHE_Integer::Init(CCPARAM_STD128_3);
    CFHE_int a, b, c, d, e, f, g;
    a = 2;
    b = 3;

    c = a + b;
    d = a - b;
    e = a * b;
    f = -a;
    g = -b;
    cout << "a == b? " << (a == b ? "yes" : "no") << endl;
    cout << "a != b? " << (a != b ? "yes" : "no") << endl;
    cout << "a >  b? " << (a >  b ? "yes" : "no") << endl;
    cout << "a >= b? " << (a >= b ? "yes" : "no") << endl;
    cout << "a <  b? " << (a <  b ? "yes" : "no") << endl;
    cout << "a <= b? " << (a <= b ? "yes" : "no") << endl;

    cout << "a : " << a << endl
         << "b : " << b << endl
         << "c : " << c << endl
         << "d : " << d << endl
         << "e : " << e << endl
         << "f : " << f << endl
         << "g : " << g << endl;
}

/*void test_echar() {
    CFHE_Echar a = 'e', b, c;
    char x;
    cout << "a is 'e', enter b: ";
    cin >> x;

    b = x;
    c = a + 1;

    cout << "a: " << a.print() << endl
         << "b: " << b.print() << endl
         << "c: " << c.print() << endl;
}*/

int main() {
    test_eint();
    return 0;
}
