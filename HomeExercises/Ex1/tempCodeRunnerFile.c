#include <stdio.h>
#include <stdint.h>

void printFloatParts(float num) {
    // Interpret the float as a 32-bit unsigned integer
    uint32_t bits = *(uint32_t*)&num;
    
    // Extract sign (1 bit)
    unsigned int sign = (bits >> 31) & 1;
    
    // Extract exponent (8 bits)
    unsigned int exponent = (bits >> 23) & 0xFF;
    
    // Extract fraction/mantissa (23 bits)
    unsigned int fraction = bits & 0x7FFFFF;
    
    // Print the extracted parts
    printf("Floating-point number: %f\n", num);
    printf("Sign: %u\n", sign);
    printf("Exponent (biased): %u\n", exponent);
    printf("Fraction (mantissa in hex): 0x%06X\n", fraction);
}

int main() {
    float num = -13.75; // Example floating-point number
    printFloatParts(num);
    return 0;
}