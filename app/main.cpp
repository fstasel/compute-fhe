#include <computefhe/ComputeFHE.h>
#include <computefhe/CFHE_Integer.h>
// #include "CFHE_Echar.h"
using namespace computefhe;
using namespace std;

void test_eint() {
    CFHE_Integer a = 13, b, c, d, e, f, g, h, i;
    int x;
    cout << "a is 13, enter b: ";
    cin >> x;

    b = x;
    c = a + b;
    d = c - b;
    e = d + 5;
    f = c - 11;
    g = -f;
    h = a * 3;
    i = f * 4;
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
         << "g : " << g << endl
         << "h : " << h << endl
         << "i : " << i << endl;
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
