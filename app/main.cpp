#include <computefhe/ComputeFHE.h>
#include "CFHE_Eint.h"

using namespace computefhe;
using namespace std;

int main() {
    CFHE_Eint a = 13, b, c, d, e, f, g, h, i;
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

    cout << "a : " << a.print() << endl
         << "b : " << b.print() << endl
         << "c : " << c.print() << endl
         << "d : " << d.print() << endl
         << "e : " << e.print() << endl
         << "f : " << f.print() << endl
         << "g : " << g.print() << endl
         << "h : " << h.print() << endl
         << "i : " << i.print() << endl;
    return 0;
}
