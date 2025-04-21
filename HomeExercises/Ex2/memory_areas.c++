#include <stdio.h>
#include <stdlib.h>

// Global (Static) Variable
int global_var = 10;
static int static_var = 20;

void check_memory() {
    // Stack Variable
    int stack_var = 30;
    
    // Heap Allocation
    int *heap_var1 = (int *)malloc(sizeof(int));
    int *heap_var2 = (int *)malloc(sizeof(int));
    
    *heap_var1 = 40;
    *heap_var2 = 50;
    
    printf("Address of Global Variable: %p\n", (void*)&global_var);
    printf("Address of Static Variable: %p\n", (void*)&static_var);
    printf("Address of Stack Variable: %p\n", (void*)&stack_var);
    printf("Address of Heap Variable 1: %p\n", (void*)heap_var1);
    printf("Address of Heap Variable 2: %p\n", (void*)heap_var2);
    
    // Check Heap Growth Direction
    if (heap_var1 < heap_var2)
        printf("Heap grows upwards.\n");
    else
        printf("Heap grows downwards.\n");
    
    // Check Stack Growth Direction
    int stack_var2;
    printf("Address of Another Stack Variable: %p\n", (void*)&stack_var2);
    if (&stack_var > &stack_var2)
        printf("Stack grows downwards.\n");
    else
        printf("Stack grows upwards.\n");
    
    // Free Allocated Memory
    free(heap_var1);
    free(heap_var2);
}

int main() {
    check_memory();
    return 0;
}

//THE PURPOSE OF THE PROGRAM IS TO VERIFY THE ADDRESSES ASSIGNED TO THE VARIOUS VARIABLES (STACK, HEAP ...)
