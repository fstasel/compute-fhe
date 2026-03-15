#pragma once

#include <computefhe/BaseArithmeticsEngine.h>
#include <computefhe/ComputeFHE.h>
#include <iostream>
using namespace std;

namespace computefhe {
  class CFHE_Eint {
  private:

  public:
    static ComputeFHE *cfhe;
    FixedPoint data;


    CFHE_Eint(int d = 0, const ArithmeticsEngineType & = AE_OPTIMIZED);
    bool operator==(const CFHE_Eint &);
    bool operator!=(const CFHE_Eint &);
    bool operator>(const CFHE_Eint &);
    bool operator>=(const CFHE_Eint &);
    bool operator<(const CFHE_Eint &);
    bool operator<=(const CFHE_Eint &);
    CFHE_Eint operator+(const CFHE_Eint &);
    CFHE_Eint operator+(uint);
    CFHE_Eint operator-(const CFHE_Eint &);
    CFHE_Eint operator-(uint);
    CFHE_Eint operator*(const CFHE_Eint &);
    CFHE_Eint operator*(uint);
    CFHE_Eint operator=(int n);
    CFHE_Eint operator=(FixedPoint n);
    CFHE_Eint operator-();
    uint print();
  };
}

/* TO-DO:
    int -> eint?
    char -> echar?
    short / long -> eshort  / elong?
    custom sized?

    EInt a = 47;
    EInt b = 13;
    cout << a + b << endl
    if ( a < b )
*/
