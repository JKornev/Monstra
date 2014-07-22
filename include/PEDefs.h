#ifndef __MONSTRA_PE_DEFS_H
#define __MONSTRA_PE_DEFS_H

#include "BaseDefs.h"

namespace Monstra {

#define MONSTRA_PE_HEADER_VIRTUAL_MAX_SIZE 0x1000
#define MONSTRA_PE_HEADER_DEFAULT_RAW_SIZE 0x400

#define MONSTRA_PE_DEFAULT_RAW_ALIGN 0x200
#define MONSTRA_PE_DEFAULT_VIRTUAL_ALIGN 0x1000

enum PEArchitecture {
	PE_32,  //PE
	PE_64,  //PE+
	PE_ROM, //isn't supported
	PE_UNK
};

#define MONSTRA_PE_INVALID_SECTOR -1
#define MONSTRA_MAX_COUNT_OF_SECTORS 0xFFFF

// Portable Executable (MSVC WindowsNT.h leak)

#pragma pack(push, 4)

#define MONSTRA_PE_IMG_DOS_SIGNATURE                 0x5A4D      // MZ
#define MONSTRA_PE_IMG_NT_SIGNATURE                  0x00004550  // PE00

#pragma pack(push, 2)
typedef struct _PE_IMAGE_DOS_HEADER {   // DOS .EXE header
	word   e_magic;                     // Magic number
	word   e_cblp;                      // Bytes on last page of file
	word   e_cp;                        // Pages in file
	word   e_crlc;                      // Relocations
	word   e_cparhdr;                   // Size of header in paragraphs
	word   e_minalloc;                  // Minimum extra paragraphs needed
	word   e_maxalloc;                  // Maximum extra paragraphs needed
	word   e_ss;                        // Initial (relative) SS value
	word   e_sp;                        // Initial SP value
	word   e_csum;                      // Checksum
	word   e_ip;                        // Initial IP value
	word   e_cs;                        // Initial (relative) CS value
	word   e_lfarlc;                    // File address of relocation table
	word   e_ovno;                      // Overlay number
	word   e_res[4];                    // Reserved words
	word   e_oemid;                     // OEM identifier (for e_oeminfo)
	word   e_oeminfo;                   // OEM information; e_oemid specific
	word   e_res2[10];                  // Reserved words
	word   e_lfanew;                    // File address of new exe header
} PEImgDosHeader, *pPEImgDosHeader;
#pragma pack(pop)

typedef struct _PE_IMAGE_FILE_HEADER {
	word    Machine;
	word    NumberOfSections;
	dword   TimeDateStamp;
	dword   PointerToSymbolTable;
	dword   NumberOfSymbols;
	word    SizeOfOptionalHeader;
	word    Characteristics;
} PEImgFileHeader, *pPEImgFileHeader;

#define MONSTRA_PE_IMG_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define MONSTRA_PE_IMG_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved externel references).
#define MONSTRA_PE_IMG_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
#define MONSTRA_PE_IMG_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define MONSTRA_PE_IMG_FILE_AGGRESIVE_WS_TRIM         0x0010  // Agressively trim working set
#define MONSTRA_PE_IMG_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define MONSTRA_PE_IMG_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
#define MONSTRA_PE_IMG_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
#define MONSTRA_PE_IMG_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define MONSTRA_PE_IMG_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define MONSTRA_PE_IMG_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define MONSTRA_PE_IMG_FILE_SYSTEM                    0x1000  // System File.
#define MONSTRA_PE_IMG_FILE_DLL                       0x2000  // File is a DLL.
#define MONSTRA_PE_IMG_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define MONSTRA_PE_IMG_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.

#define MONSTRA_PE_IMG_FILE_MACHINE_UNKNOWN           0
#define MONSTRA_PE_IMG_FILE_MACHINE_I386              0x014c  // Intel 386.
#define MONSTRA_PE_IMG_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
#define MONSTRA_PE_IMG_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
#define MONSTRA_PE_IMG_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
#define MONSTRA_PE_IMG_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
#define MONSTRA_PE_IMG_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define MONSTRA_PE_IMG_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
#define MONSTRA_PE_IMG_FILE_MACHINE_SH3DSP            0x01a3
#define MONSTRA_PE_IMG_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
#define MONSTRA_PE_IMG_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
#define MONSTRA_PE_IMG_FILE_MACHINE_SH5               0x01a8  // SH5
#define MONSTRA_PE_IMG_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
#define MONSTRA_PE_IMG_FILE_MACHINE_THUMB             0x01c2
#define MONSTRA_PE_IMG_FILE_MACHINE_AM33              0x01d3
#define MONSTRA_PE_IMG_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
#define MONSTRA_PE_IMG_FILE_MACHINE_POWERPCFP         0x01f1
#define MONSTRA_PE_IMG_FILE_MACHINE_IA64              0x0200  // Intel 64
#define MONSTRA_PE_IMG_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define MONSTRA_PE_IMG_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define MONSTRA_PE_IMG_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define MONSTRA_PE_IMG_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define MONSTRA_PE_IMG_FILE_MACHINE_AXP64             MONSTRA_PE_IMG_FILE_MACHINE_ALPHA64
#define MONSTRA_PE_IMG_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define MONSTRA_PE_IMG_FILE_MACHINE_CEF               0x0CEF
#define MONSTRA_PE_IMG_FILE_MACHINE_EBC               0x0EBC  // EFI Byte Code
#define MONSTRA_PE_IMG_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define MONSTRA_PE_IMG_FILE_MACHINE_M32R              0x9041  // M32R little-endian
#define MONSTRA_PE_IMG_FILE_MACHINE_CEE               0xC0EE

typedef struct _PE_IMAGE_DATA_DIRECTORY {
	dword   VirtualAddress;
	dword   Size;
} PEImgDataDir, *pPEImgDataDir;

#define MONSTRA_PE_IMG_DIR_ENTRIES    16

typedef struct _PE_IMAGE_OPTIONAL_HEADER32 {
	// Standard fields.
	word    Magic;
	byte    MajorLinkerVersion;
	byte    MinorLinkerVersion;
	dword   SizeOfCode;
	dword   SizeOfInitializedData;
	dword   SizeOfUninitializedData;
	dword   AddressOfEntryPoint;
	dword   BaseOfCode;
	dword   BaseOfData;
	// NT additional fields.
	dword   ImageBase;
	dword   SectionAlignment;
	dword   FileAlignment;
	word    MajorOperatingSystemVersion;
	word    MinorOperatingSystemVersion;
	word    MajorImageVersion;
	word    MinorImageVersion;
	word    MajorSubsystemVersion;
	word    MinorSubsystemVersion;
	dword   Win32VersionValue;
	dword   SizeOfImage;
	dword   SizeOfHeaders;
	dword   CheckSum;
	word    Subsystem;
	word    DllCharacteristics;
	dword   SizeOfStackReserve;
	dword   SizeOfStackCommit;
	dword   SizeOfHeapReserve;
	dword   SizeOfHeapCommit;
	dword   LoaderFlags;
	dword   NumberOfRvaAndSizes;
	PEImgDataDir DataDirectory[MONSTRA_PE_IMG_DIR_ENTRIES];
} PEImgOptHeader32, *pPEImgOptHeader32;

typedef struct _PE_IMAGE_OPTIONAL_HEADER64 {
	word    Magic;
	byte    MajorLinkerVersion;
	byte    MinorLinkerVersion;
	dword   SizeOfCode;
	dword   SizeOfInitializedData;
	dword   SizeOfUninitializedData;
	dword   AddressOfEntryPoint;
	dword   BaseOfCode;
	qword   ImageBase;
	dword   SectionAlignment;
	dword   FileAlignment;
	word    MajorOperatingSystemVersion;
	word    MinorOperatingSystemVersion;
	word    MajorImageVersion;
	word    MinorImageVersion;
	word    MajorSubsystemVersion;
	word    MinorSubsystemVersion;
	dword   Win32VersionValue;
	dword   SizeOfImage;
	dword   SizeOfHeaders;
	dword   CheckSum;
	word    Subsystem;
	word    DllCharacteristics;
	qword   SizeOfStackReserve;
	qword   SizeOfStackCommit;
	qword   SizeOfHeapReserve;
	qword   SizeOfHeapCommit;
	dword   LoaderFlags;
	dword   NumberOfRvaAndSizes;
	PEImgDataDir DataDirectory[MONSTRA_PE_IMG_DIR_ENTRIES];
} PEImgOptHeader64, *pPEImgOptHeader64;

#define MONSTRA_PE_IMG_NT_OPTIONAL_HDR32_MAGIC        0x10b
#define MONSTRA_PE_IMG_NT_OPTIONAL_HDR64_MAGIC        0x20b
#define MONSTRA_PE_IMG_ROM_OPTIONAL_HDR_MAGIC         0x107

#define MONSTRA_PE_IMG_DATADIR_OPT32_OFFSET 24 * sizeof(dword)
#define MONSTRA_PE_IMG_DATADIR_OPT64_OFFSET 28 * sizeof(dword)

#if defined(MONSTRA_SYSTEM_PLATFORM_X64)
typedef PEImgOptHeader64                  PEImgOptHeader;
typedef pPEImgOptHeader64                 pPEImgOptHeader;
#define MONSTRA_PE_IMG_NT_OPT_HDR_MAGIC   MONSTRA_PE_IMG_NT_OPT_HDR64_MAGIC
#else
typedef PEImgOptHeader32                  PEImgOptHeader;
typedef pPEImgOptHeader32                 pPEImgOptHeader;
#define MONSTRA_PE_IMG_NT_OPT_HDR_MAGIC   MONSTRA_PE_IMG_NT_OPT_HDR32_MAGIC
#endif

typedef struct _PE_IMAGE_NT_HEADERS64 {
	dword Signature;
	PEImgFileHeader FileHeader;
	PEImgOptHeader64 OptionalHeader;
} PEImgNtHeaders64, *pPEImgNtHeaders64;

typedef struct _PE_IMAGE_NT_HEADERS {
	dword Signature;
	PEImgFileHeader FileHeader;
	PEImgOptHeader32 OptionalHeader;
} PEImgNtHeaders32, *pPEImgNtHeaders32;


#if defined(MONSTRA_SYSTEM_PLATFORM_X64)
typedef PEImgNtHeaders64                  PEImgHeaders;
typedef pPEImgNtHeaders64                 pPEImgHeaders;
#else
typedef PEImgNtHeaders32                  PEImgHeaders;
typedef pPEImgNtHeaders32                 pPEImgHeaders;
#endif

// Subsystem Values
#define MONSTRA_PE_IMG_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define MONSTRA_PE_IMG_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define MONSTRA_PE_IMG_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define MONSTRA_PE_IMG_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define MONSTRA_PE_IMG_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define MONSTRA_PE_IMG_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
#define MONSTRA_PE_IMG_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
#define MONSTRA_PE_IMG_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
#define MONSTRA_PE_IMG_SUBSYSTEM_EFI_APPLICATION      10  //
#define MONSTRA_PE_IMG_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
#define MONSTRA_PE_IMG_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
#define MONSTRA_PE_IMG_SUBSYSTEM_EFI_ROM              13
#define MONSTRA_PE_IMG_SUBSYSTEM_XBOX                 14
#define MONSTRA_PE_IMG_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

// DllCharacteristics Entries
#define MONSTRA_PE_IMG_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
#define MONSTRA_PE_IMG_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
#define MONSTRA_PE_IMG_LIBRARY_THREAD_INIT             0x0004     // Reserved.
#define MONSTRA_PE_IMG_LIBRARY_THREAD_TERM             0x0008     // Reserved.
#define MONSTRA_PE_IMG_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040     // DLL can move.
#define MONSTRA_PE_IMG_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080     // Code Integrity Image
#define MONSTRA_PE_IMG_DLLCHARACTERISTICS_NX_COMPAT    0x0100     // Image is NX compatible
#define MONSTRA_PE_IMG_DLLCHARACTERISTICS_NO_ISOLATION 0x0200     // Image understands isolation and doesn't want it
#define MONSTRA_PE_IMG_DLLCHARACTERISTICS_NO_SEH       0x0400     // Image does not use SEH.  No SE handler may reside in this image
#define MONSTRA_PE_IMG_DLLCHARACTERISTICS_NO_BIND      0x0800     // Do not bind this image.
//                                                     0x1000     // Reserved.
#define MONSTRA_PE_IMG_DLLCHARACTERISTICS_WDM_DRIVER   0x2000     // Driver uses WDM model
//                                                     0x4000     // Reserved.
#define MONSTRA_PE_IMG_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000

// Directory Entries
#define MONSTRA_PE_IMG_DIR_ENTRY_EXPORT          0   // Export Directory
#define MONSTRA_PE_IMG_DIR_ENTRY_IMPORT          1   // Import Directory
#define MONSTRA_PE_IMG_DIR_ENTRY_RESOURCE        2   // Resource Directory
#define MONSTRA_PE_IMG_DIR_ENTRY_EXCEPTION       3   // Exception Directory
#define MONSTRA_PE_IMG_DIR_ENTRY_SECURITY        4   // Security Directory
#define MONSTRA_PE_IMG_DIR_ENTRY_BASERELOC       5   // Base Relocation Table
#define MONSTRA_PE_IMG_DIR_ENTRY_DEBUG           6   // Debug Directory
//      MONSTRA_PE_IMG_DIR_ENTRY_COPYRIGHT       7   // (X86 usage)
#define MONSTRA_PE_IMG_DIR_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define MONSTRA_PE_IMG_DIR_ENTRY_GLOBALPTR       8   // RVA of GP
#define MONSTRA_PE_IMG_DIR_ENTRY_TLS             9   // TLS Directory
#define MONSTRA_PE_IMG_DIR_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define MONSTRA_PE_IMG_DIR_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define MONSTRA_PE_IMG_DIR_ENTRY_IAT            12   // Import Address Table
#define MONSTRA_PE_IMG_DIR_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define MONSTRA_PE_IMG_DIR_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

#define MONSTRA_PE_IMG_SHORT_NAME_LEN            8

typedef struct _PE_IMAGE_SECTION_HEADER {
	byte    Name[MONSTRA_PE_IMG_SHORT_NAME_LEN];
	union {
		dword PhysicalAddress;
		dword VirtualSize;
	} Misc;
	dword   VirtualAddress;
	dword   SizeOfRawData;
	dword   PointerToRawData;
	dword   PointerToRelocations;
	dword   PointerToLinenumbers;
	word    NumberOfRelocations;
	word    NumberOfLinenumbers;
	dword   Characteristics;
} PEImgSectionHeader, *pPEImgSectionHeader;


// Section characteristics.
//      MONSTRA_PE_IMG_SCN_TYPE_REG                   0x00000000  // Reserved.
//      MONSTRA_PE_IMG_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      MONSTRA_PE_IMG_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      MONSTRA_PE_IMG_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define MONSTRA_PE_IMG_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
//      MONSTRA_PE_IMG_SCN_TYPE_COPY                  0x00000010  // Reserved.
#define MONSTRA_PE_IMG_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define MONSTRA_PE_IMG_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define MONSTRA_PE_IMG_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.
#define MONSTRA_PE_IMG_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define MONSTRA_PE_IMG_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
//      MONSTRA_PE_IMG_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define MONSTRA_PE_IMG_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define MONSTRA_PE_IMG_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
//                                                    0x00002000  // Reserved.
//      MONSTRA_PE_IMG_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define MONSTRA_PE_IMG_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define MONSTRA_PE_IMG_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
#define MONSTRA_PE_IMG_SCN_MEM_FARDATA                0x00008000
//      MONSTRA_PE_IMG_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define MONSTRA_PE_IMG_SCN_MEM_PURGEABLE              0x00020000
#define MONSTRA_PE_IMG_SCN_MEM_16BIT                  0x00020000
#define MONSTRA_PE_IMG_SCN_MEM_LOCKED                 0x00040000
#define MONSTRA_PE_IMG_SCN_MEM_PRELOAD                0x00080000
#define MONSTRA_PE_IMG_SCN_ALIGN_1BYTES               0x00100000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_2BYTES               0x00200000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_4BYTES               0x00300000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_8BYTES               0x00400000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define MONSTRA_PE_IMG_SCN_ALIGN_32BYTES              0x00600000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_64BYTES              0x00700000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_128BYTES             0x00800000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_256BYTES             0x00900000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_512BYTES             0x00A00000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_1024BYTES            0x00B00000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_2048BYTES            0x00C00000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_4096BYTES            0x00D00000  //
#define MONSTRA_PE_IMG_SCN_ALIGN_8192BYTES            0x00E00000  //
// Unused                                             0x00F00000
#define MONSTRA_PE_IMG_SCN_ALIGN_MASK                 0x00F00000
#define MONSTRA_PE_IMG_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define MONSTRA_PE_IMG_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define MONSTRA_PE_IMG_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define MONSTRA_PE_IMG_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define MONSTRA_PE_IMG_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define MONSTRA_PE_IMG_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define MONSTRA_PE_IMG_SCN_MEM_READ                   0x40000000  // Section is readable.
#define MONSTRA_PE_IMG_SCN_MEM_WRITE                  0x80000000  // Section is writeable.
// TLS Chaacteristic Flags
#define MONSTRA_PE_IMG_SCN_SCALE_INDEX                0x00000001  // Tls index is scaled

// Export Format
typedef struct _PE_IMAGE_EXPORT_DIRECTORY {
	dword   Characteristics;
	dword   TimeDateStamp;
	word    MajorVersion;
	word    MinorVersion;
	dword   Name;
	dword   Base;
	dword   NumberOfFunctions;
	dword   NumberOfNames;
	dword   AddressOfFunctions;     // RVA from base of image
	dword   AddressOfNames;         // RVA from base of image
	dword   AddressOfNameOrdinals;  // RVA from base of image
} PEImgExportDir, *pPEImgExportDir;

// Import Format
typedef struct _PE_IMAGE_IMPORT_BY_NAME {
	word    Hint;
	byte    Name[1];
} PEImgImportByName, *pPEImgImportByName;

#pragma pack(push, 8)
typedef struct _PE_IMAGE_THUNK_DATA64 {
	union {
		qword ForwarderString;  // PBYTE 
		qword Function;         // PDWORD
		qword Ordinal;
		qword AddressOfData;    // PIMAGE_IMPORT_BY_NAME
	} u1;
} PEImgThunkData64, *pPEImgThunkData64;
#pragma pack(pop)

typedef struct _PE_IMAGE_THUNK_DATA32 {
	union {
		dword ForwarderString;      // PBYTE 
		dword Function;             // PDWORD
		dword Ordinal;
		dword AddressOfData;        // PIMAGE_IMPORT_BY_NAME
	} u1;
} PEImgThunkData32, *pPEImgThunkData32;

#define MONSTRA_PE_IMG_ORDINAL_FLAG64 0x8000000000000000
#define MONSTRA_PE_IMG_ORDINAL_FLAG32 0x80000000
#define MONSTRA_PE_IMG_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define MONSTRA_PE_IMG_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define MONSTRA_PE_IMG_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define MONSTRA_PE_IMG_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)



// Based relocation format.
typedef struct _PE_IMAGE_BASE_RELOCATION {
    dword   VirtualAddress;
    dword   SizeOfBlock;
//  word    TypeOffset[1];
} PEImgBaseReloc, *pPEImgBaseReloc;

// Based relocation types.
#define MONSTRA_PE_IMG_REL_BASED_ABSOLUTE              0
#define MONSTRA_PE_IMG_REL_BASED_HIGH                  1
#define MONSTRA_PE_IMG_REL_BASED_LOW                   2
#define MONSTRA_PE_IMG_REL_BASED_HIGHLOW               3
#define MONSTRA_PE_IMG_REL_BASED_HIGHADJ               4
#define MONSTRA_PE_IMG_REL_BASED_MIPS_JMPADDR          5
#define MONSTRA_PE_IMG_REL_BASED_MIPS_JMPADDR16        9
#define MONSTRA_PE_IMG_REL_BASED_IA64_IMM64            9
#define MONSTRA_PE_IMG_REL_BASED_DIR64                 10

#pragma pack(pop) //PE end

// Pointers

template<typename T> class io_ptr;

typedef io_ptr<uint8_t>            PEBuffer;
typedef io_ptr<PEImgDosHeader>     PEImgDosHeader_ptr;
typedef io_ptr<PEImgFileHeader>    PEImgFileHeader_ptr;
typedef io_ptr<PEImgOptHeader32>   PEImgOptHeader32_ptr;
typedef io_ptr<PEImgOptHeader64>   PEImgOptHeader64_ptr;
typedef io_ptr<PEImgDataDir>       PEImgDataDir_ptr;
typedef io_ptr<PEImgSectionHeader> PEImgSectionHeader_ptr;
typedef io_ptr<PEImgNtHeaders32>   PEImgNtHeaders32_ptr;
typedef io_ptr<PEImgNtHeaders64>   PEImgNtHeaders64_ptr;

};/*Monstra namespace*/

#endif
