#pragma once

#include "BaseArithmeticsEngine.h"
#include "ComputeFHE.h"
#include <iostream>
using namespace std;

class CFHE_Echar {
private:
  static ComputeFHE *cfhe;
  FixedPoint data;

public:
  CFHE_Echar(char d = 0, const ArithmeticsEngineType & = AE_OPTIMIZED);
  bool operator==(const CFHE_Echar &);
  bool operator!=(const CFHE_Echar &);
  bool operator>(const CFHE_Echar &);
  bool operator>=(const CFHE_Echar &);
  bool operator<(const CFHE_Echar &);
  bool operator<=(const CFHE_Echar &);
  CFHE_Echar operator+(const CFHE_Echar &);
  CFHE_Echar operator+(uint);
  CFHE_Echar operator-(const CFHE_Echar &);
  CFHE_Echar operator-(uint);
  CFHE_Echar operator*(const CFHE_Echar &);
  CFHE_Echar operator*(uint);
  CFHE_Echar operator=(char n);
  CFHE_Echar operator=(FixedPoint n);
  CFHE_Echar operator-();
  char print();
};

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