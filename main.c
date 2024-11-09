#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#pragma code_seg(push, r1, ".text")
uint32_t fnv321a(const char *str) {
   uint32_t hash = 0x811c9dc5;

   while (*str != 0) {
      hash ^= *str;
      hash *= 0x1000193;
      ++str;
   }

   return hash;
}

int main(int argc, char *argv[]) {
   return 0;
}
#pragma code_seg(pop, r1)

#pragma code_seg(push, r1, ".ztext")
uint32_t target_function(void) {
   return 0xDEADBEEF;
}
#pragma code_seg(pop, r1)
