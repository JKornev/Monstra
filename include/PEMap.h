#ifndef __MONSTRA_PE_MAP_H
#define __MONSTRA_PE_MAP_H

#include "PEDefs.h"

#include <vector>

namespace Monstra {

class PEHeaderParser;

enum {
	PE_MAP_INVALID,
	PE_MAP_HEADER,
	PE_MAP_SECTOR,
};

/*
typedef struct _PEMapEntry {
	uint16_t type;
	uint16_t sect_num;
	dword    rva;
	uint32_t rva_size;
	dword    raw;
	uint32_t raw_size;

	_PEMapEntry(
		uint16_t map_type = PE_MAP_INVALID, 
		uint16_t section_num = -1,
		dword voffset = 0, 
		uint32_t vsize = 0, 
		dword roffset = 0, 
		uint32_t rsize = 0
	) : type(map_type), sect_num(section_num), rva(voffset), 
	rva_size(vsize), raw(roffset), raw_size(rsize) { }

} PEMapEntry, *pPEMapEntry;*/

/*
typedef struct _PEBlockEntry {
	uint16_t type;
	uint16_t sect_num;
	dword    offset;
	uint32_t size;

	_PEBlockEntry(
		uint16_t map_type = PE_MAP_INVALID, 
		uint16_t section_num = -1, 
		dword ofst = 0, 
		uint32_t sz = 0
	) : type(map_type), sect_num(section_num), offset(ofst), size(sz) { }
} PEBlockEntry, *pPEBlockEntry;*/

typedef struct _PEBlockEntry {
	uint16_t type;
	uint16_t sect_num;
	dword    rva;
	uint32_t rva_size;
	dword    raw;
	uint32_t raw_size;

	_PEBlockEntry(
		uint16_t map_type = PE_MAP_INVALID, 
		uint16_t section_num = -1,
		dword voffset = 0, 
		uint32_t vsize = 0, 
		dword roffset = 0, 
		uint32_t rsize = 0
	) : type(map_type), sect_num(section_num), rva(voffset), 
		rva_size(vsize), raw(roffset), raw_size(rsize) { }
} PEBlockEntry, *pPEBlockEntry;

class PEMap : public std::vector<PEBlockEntry> {
public:
	PEMap();

	bool Load(PEHeaderParser &parser, uint32_t virt_align = 0, uint32_t raw_align = 0);
	void Clear();

	void Realign(uint32_t virt_align = 0, uint32_t raw_align = 0);
	uint32_t GetRawAlign() const;
	uint32_t GetVirtualAlign() const;

	// Convert
	//bool ConvRvaToRaw(dword rva, PEBlockEntry& block);
	bool GetBlockInxByRva(dword rva, uint32_t& inx);
	bool GetRelativeBlockByRva(dword rva, PEBlockEntry& block);

	//bool ConvRawToRva(dword raw, std::vector<PEBlockEntry> &blocks);
	bool GetBlockInxByRaw(dword raw, std::vector<uint32_t> &inxs);
	bool GetRelativeBlockByRaw(dword rva, std::vector<PEBlockEntry> &blocks);

	// Size
	uint32_t CalcVirtualSize();
	uint32_t CalcRawSize();

private:
	uint32_t _virt_align;
	uint32_t _raw_align;

private:
	void Align(dword &offset, uint32_t &size, uint32_t align_base, bool inc_align);

};

};//Monstra

#endif
