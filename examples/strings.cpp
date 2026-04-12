#include <computefhe/ComputeFHE.h>
#include <iostream>

using namespace computefhe;
using namespace std;

#define SIMULATOR_MODE 1

using Echar = EInt<u_char, 8, false>;

void find_and_replace(Evector<Echar> &str, Echar o, Echar n) {
    for(size_t i = 0; i < str.size();i++) {
        Eif(str[i] == o)
            str[i] = n;
    }
}

Eint8 count_letters(Evector<Echar> &str, Echar c) {
    Eint8 count = 0;
    for(size_t i = 0; i < str.size();i++) {
        Eif(str[i] == c)
            count++;
    }
    return count;
}

Eint8 seek(Evector<Echar> &str, Echar c) {
    Eint8 pos = -1;
    for (size_t i = 0; i < str.size(); i++) {
        Eif(str[i] == c && pos == -1) {
            pos = i;
        }
    }
    return pos;
}

void to_uppercase(Evector<Echar>& str) {
    for(size_t i = 0; i<str.size(); i++) {
        Eif(str[i] >= 'a' && str[i] <= 'z')
            str[i] += 'A' - 'a';
    }
}

void to_lowercase(Evector<Echar>& str) {
    for(size_t i = 0; i<str.size(); i++) {
        Eif(str[i] >= 'A' && str[i] <= 'Z')
            str[i] += 'a' - 'A';
    }
}

int main() {
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, true, SIMULATOR_MODE);

    string str0 = "Lorem ipsum, dolor sit amet.";
    Evector<Echar> e_str(str0.begin(), str0.end());
    
    cout << "Original string: " << str0 << endl;
    
    find_and_replace(e_str, 'o', 'n');
    vector<u_char> str1(e_str.begin(), e_str.end());
    cout << "New string     : " << string(str1.begin(), str1.end()) << endl;

    Eint8 cnt = count_letters(e_str, 'e');
    cout << "The letter 'e' occurs " << cnt << " times." << endl;
    cout << "Position of letter 'e': " << seek(e_str, 'e') << endl;
    cout << "Position of letter 'E': " << seek(e_str, 'E') << endl;

    to_uppercase(e_str);
    vector<u_char> str2(e_str.begin(), e_str.end());
    cout << "Uppercase: "<< string(str2.begin(), str2.end()) << endl;

    to_lowercase(e_str);
    vector<u_char> str3(e_str.begin(), e_str.end());
    cout << "Lowercase: "<< string(str3.begin(), str3.end()) << endl;

    if (SIMULATOR_MODE) {
        cfhe_base->GetSimulator()->PrintStats();
    }

    computefhe::Finalize();
    return 0;
}