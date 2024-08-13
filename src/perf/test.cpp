#include <iostream>
using namespace std;



int main() {

    int portfolio = 0;
    int years = 50;

    for (int i = 0; i < years; i++) {
        portfolio += 30000;
        portfolio *= 1.05;
    }

    cout << "Portfolio value after " << years << " years: " << portfolio << endl;
    return 0;
}
