#ifndef __MONSTRA_PE_DIR_RELOCS_H
#define __MONSTRA_PE_DIR_RELOCS_H

#include "PEDefs.h"
#include "PEMap.h"
#include "PEParser.h"
#include "IOPointer.h"
#include "ErrorHandler.h"

#include <list>
#include <vector>
#include <exception>

namespace Monstra {

// Parser

typedef std::vector<PEImgBaseReloc_ptr> RelocsEntryInfoList;
typedef bool (MONSTRA_CDECL *enum_relocs_callback)(const PEBuffer block, uint32_t block_inx, 
	uint32_t block_base, word type, dword rva, void* params);

class PERelocsParser : public MONSTRA_ERROR_CTRL {
public:
	PERelocsParser();
	~PERelocsParser();

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
	bool ChangeImagebase(PESourceInterface* src, UAddress new_base);
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

typedef struct _RelocsTableEntry {
	uint16_t type;
	uint16_t offset;
	_RelocsTableEntry(uint16_t t, uint16_t o) : type(t), offset(o) { }
} RelocsTableEntry, *pRelocsTableEntry;

typedef struct _RelocsTable {
	dword rva;
	std::vector<RelocsTableEntry> entry;

	_RelocsTable(dword voffset) : rva(voffset) { }

	dword get_rel(uint16_t inx, uint16_t* type = 0) 
	{
		if (inx > entry.size())
			throw std::exception("relocs: out of range");
		if (type != 0)
			*type = entry[inx].type;
		return rva + entry[inx].offset;
	}
} RelocsTable, *pRelocsTable;

class PERelocs : public std::vector<RelocsTable> {
public:
	
	PERelocs();
	~PERelocs();

	bool Load(PERelocsParser &parser);
	void Clear();

	UAddress GetImagebase() const;
	void SetImagebase(UAddress imgbase);

	void Commit(void* buf, uint32_t size, UAddress new_base) const;

private:
	UAddress _imgbase;

private:
	static bool MONSTRA_CDECL enum_callback(const PEBuffer block, uint32_t block_inx, 
		uint32_t block_base, word type, dword rva, void* params);

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
