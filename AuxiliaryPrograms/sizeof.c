#include <stdint.h>
#include <stdio.h>
#include <x86intrin.h>

int main(int argc, char *argv[])
{
    printf("sizeof(int) %zu\n", sizeof(int));
    printf("sizeof(long int) %zu\n", sizeof(long int));
    printf("sizeof(long long int) %zu\n", sizeof(long long int));
    printf("sizeof(size_t) %zu\n", sizeof(size_t));
    printf("sizeof(__m128i) %zu\n", sizeof(__m128i));
    printf("sizeof(void *) %zu\n", sizeof(void *));
    printf("sizeof(uint8_t *) %zu\n", sizeof(uint8_t *));
    printf("sizeof(__m128i *) %zu\n", sizeof(__m128i *));

    return 0;
}

// end of file
