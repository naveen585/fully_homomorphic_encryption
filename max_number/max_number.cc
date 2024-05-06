#include "max_number.h"

#pragma hls_top
int max_number(int &a, int &b) { return (a > b) ? a : b; }
