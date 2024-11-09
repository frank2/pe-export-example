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

uint8_t *get_import_by_hash(uint8_t *module, uint32_t hash) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;
   PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)&module[dos_header->e_lfanew];
   PIMAGE_DATA_DIRECTORY export_datadir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
   PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)&module[export_datadir->VirtualAddress];

   return NULL;
}

int main(int argc, char *argv[]) {
   uint32_t (*ptr)(void) = target_function;
   uint32_t value = ptr();
}
#pragma code_seg(pop, r1)

#pragma code_seg(push, r1, ".ztext")
uint32_t target_function(void) {
   return 0xDEADBEEF;
}
#pragma code_seg(pop, r1)
