#ifndef __MONSTRA_PE_DIR_RELOCS_H
#define __MONSTRA_PE_DIR_RELOCS_H

#include "PEDefs.h"
#include "PEMap.h"
#include "PEParser.h"
#include "IOPointer.h"
#include "ErrorHandler.h"

#include <list>
#include <vector>

namespace Monstra {

// Parser

typedef std::vector<PEImgBaseReloc_ptr> RelocsEntryInfoList;
typedef bool (MONSTRA_CDECL *enum_relocs_callback)(const PEBuffer block, word type, dword rva, void* params);

class PEDirRelocsParser : public MONSTRA_ERROR_CTRL {
public:
	PEDirRelocsParser();
	~PEDirRelocsParser();

	bool Parse(PESourceInterface* src, dword dir_rva, uint32_t dir_size, UAddress imgbase);
	void Clear();

	bool IsParsed() const;

	PEBuffer& GetDir(dword* dir_rva = 0);
	const PEBuffer& GetDir(dword* dir_rva = 0) const;

	uint32_t GetCountOfBlocks() const;
	UAddress GetImageBase() const;

	bool EnumRelocs(enum_relocs_callback callback, void *params);
	bool EnumRelocs(enum_relocs_callback callback, void *params) const;

	// misc
	bool ChangeImagebase(UAddress new_base);
	uint32_t GetChecksum() const;

private:
	bool _parsed;
	
	dword           _dir_offset;
	uint32_t        _dir_size;
	uint32_t		_blocks;
	PEBuffer        _block_entry;
	UAddress        _imgbase;
};

// Container

class PEDirRelocs {
public:

};

// Builder

class PEDirRelocsBuilder : public MONSTRA_ERROR_CTRL {
public:

};

/*
// Parser

typedef std::vector<pPEImgBaseReloc> RelocsEntryInfoList;
typedef bool (MOSTRA_CDECL *enum_relocs_callback)(pPEImgBaseReloc block_entry, word type, dword voffset, void* params);


class PEDirRelocsParser : public MONSTRA_ERROR_CTRL {
public:

	PEDirRelocsParser();
	~PEDirRelocsParser();

	// open 

	bool Parse(PEParserSourceInterface& src, dword dir_offset, uint32_t dir_size, UAddress imgbase);
	void Clear();

	bool IsParsed() const;

	// info

	pPEImgBaseReloc GetDir(dword* offset = 0, uint32_t* size = 0) const;
	unsigned int GetCountOfBlocks() const;
	UAddress GetImageBase() const;

	bool FindBlocks(dword voffset, RelocsEntryInfoList& blocks);
	bool FindBlocksInRange(dword voffset, unsigned int size, RelocsEntryInfoList& blocks);

	bool EnumRelocs(enum_relocs_callback callback, void *params);
	
	// misc

	bool ChangeImagebase(UAddress new_base);

	unsigned int GetChecksum() const;

private:

	bool _parsed;
	PEParserSourceInterface* _src;

	dword           _dir_offset;
	uint32_t        _dir_size;
	uint32_t		_blocks;
	pPEImgBaseReloc _block_entry;
	UAddress        _imgbase;

};

// Container

//import / export
typedef struct _Reloc {
	word type;
	dword voffset;
	_Reloc(word t = 0, dword v = 0) : type(t), voffset(v) { }
} Reloc, *pReloc;

// table defs
typedef struct _RelocEntry {
	word type;
	word offset;
} RelocEntry, *pRelocEntry;

typedef struct _RelocsTableEntry {
	dword base;
	std::list<RelocEntry> relocs;
} RelocsTableEntry, *pRelocsTableEntry;

typedef std::list<RelocsTableEntry> RelocsTable;
typedef RelocsTable* pRelocsTable;


class PEDirRelocs {
public:

	PEDirRelocs();
	~PEDirRelocs();

	bool Load(PEDirRelocsParser& parser);
	void Clear();

	void Export(std::vector<Reloc>& relocs) const;
	void Import(std::vector<Reloc>& relocs);

	UAddress GetImagebase() const;
	void SetImagebase(UAddress addr);

	void Commit(void* buf, uint32_t size, UAddress base);

private:

	RelocsTable _table;
	UAddress _imgbase;

};

// Builder

class PEDirRelocsBuilder : public MONSTRA_ERROR_CTRL {
public:

private:

};*/

};/*Monstra namespace*/

#endif
