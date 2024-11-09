#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <windows.h>

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
   uint32_t *functions = (uint32_t *)&module[export_dir->AddressOfFunctions];
   uint32_t *names = (uint32_t *)&module[export_dir->AddressOfNames];
   uint16_t *name_ordinals = (uint16_t *)&module[export_dir->AddressOfNameOrdinals];

   for (size_t i=0; i<export_dir->NumberOfFunctions; ++i) {
      if (fnv321a((const char *)&module[names[name_ordinals[i]]]) != hash)
         continue;
      
      if (functions[i] >= export_datadir->VirtualAddress && functions[i] < export_datadir->VirtualAddress+export_datadir->Size) {
         const char *forwarder = (const char *)&module[functions[i]];
         char *forwarder_mut = malloc(strlen(forwarder)+1);
         memcpy(forwarder_mut, forwarder, strlen(forwarder)+1);
         char *func;

         for (size_t j=0; j<strlen(forwarder); ++j) {
            if (forwarder_mut[j] != '.')
               continue;

            forwarder_mut[j] = 0;
            func = &forwarder_mut[j+1];
            break;
         }

         HMODULE forward_dll = LoadLibraryA(forwarder_mut);
         uint8_t *proc = (uint8_t *)GetProcAddress(forward_dll, func);
         free(forwarder_mut);

         return proc;
      }
         
      return &module[functions[i]];
   }

   return NULL;
}

int main(int argc, char *argv[]) {
   uint8_t *kernel32 = (uint8_t *)GetModuleHandleA("kernel32");
   uint8_t *msvcrt = LoadLibraryA("msvcrt");
   void * (*cpy)(void *, void *, size_t) = (void *(*)(void *, void *, size_t))get_import_by_hash(msvcrt, 0xa45cec64);
   int (*cmp)(void *, void *, size_t) = (int *(*)(void *, void *, size_t))get_import_by_hash(msvcrt, 0xaf3caa0a);
   void * (*valloc)(void *, size_t, uint32_t, uint32_t) = (void *(*)(void *, size_t, uint32_t, uint32_t))get_import_by_hash(kernel32, 0x03285501);

   uint8_t *this = (uint8_t *)GetModuleHandle(NULL);
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)this;
   PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)&this[dos_header->e_lfanew];
   PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)&this[dos_header->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader];

   void *target_buffer;
   
   for (size_t i=0; i<nt_headers->FileHeader.NumberOfSections; ++i) {
      if (cmp(&sections[i].Name[0], ".beef", 5) != 0)
         continue;

      target_buffer = valloc(NULL, sections[i].Misc.VirtualSize, MEM_COMMIT, PAGE_EXECUTE_READ);
      cpy(target_buffer, &this[sections[i].VirtualAddress], sections[i].Misc.VirtualSize);
      break;
   }

   uint32_t beef = ((uint32_t (*)(void))target_buffer)();

   return beef != 0xDEADBEEF;      
}

#pragma section(".beef", read, execute)
__declspec(code_seg(".beef")) uint32_t target_function(void) {
   return 0xDEADBEEF;
}
#pragma comment(linker, "/include:target_function")
