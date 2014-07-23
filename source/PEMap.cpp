#include "PEMap.h"
#include "PEHeader.h"

using namespace std;

namespace Monstra {

PEMap::PEMap() :
	_virt_align(0),
	_raw_align(0)
{
}

bool PEMap::Load(PEHeaderParser &parser, uint32_t virt_align, uint32_t raw_align)
{
	PEBlockEntry entry;

	if (!parser.IsParsed()) {
		return false;
	}

	// set alignment
	if (virt_align != 0) {
		if (!CheckSquare(virt_align)) {
			return false;
		}
		_virt_align = virt_align;
	} else {
		_virt_align = parser.GetVirtualAlignment();
	}

	if (raw_align != 0) {
		if (!CheckSquare(raw_align)) {
			return false;
		}
		_raw_align = raw_align;
	} else {
		_raw_align = parser.GetRawAlignment();
	}

	clear();

	//map header
	entry.type = PE_MAP_HEADER;
	entry.rva = 0;
	entry.rva_size = MONSTRA_PE_HEADER_VIRTUAL_MAX_SIZE;
	entry.raw = 0;
	entry.raw_size = parser.GetHeaderSize();
	entry.sect_num = -1;
	push_back(entry);

	//map sectors
	PEImgSectionHeader_ptr& psect = parser.GetSectors();
	for (uint16_t i = 0, count = psect.count(); i < count; i++) {
		entry.type = PE_MAP_SECTOR;
		entry.rva = psect[i].VirtualAddress;
		entry.rva_size = psect[i].Misc.VirtualSize;
		entry.raw = psect[i].PointerToRawData;
		entry.raw_size = psect[i].SizeOfRawData;
		entry.sect_num = i;
		push_back(entry);
	}

	Realign(_virt_align, _raw_align);

	return true;
}

void PEMap::Clear()
{
	_virt_align = 0;
	_raw_align = 0;
	clear();
}

void PEMap::Realign(uint32_t virt_align, uint32_t raw_align)
{//TOFIX некорректное выравнивание данных например 0x1000 -> 0x2000
	vector<PEBlockEntry>& map = *this;
	for (int i = 0, count = size(); i < count; i++) {
		Align(map[i].rva, map[i].rva_size, virt_align, _virt_align < virt_align && _virt_align != 0);
		Align(map[i].raw, map[i].raw_size, raw_align, _raw_align < raw_align && _raw_align != 0);

		if (map[i].rva_size < map[i].raw_size) {
			map[i].raw_size = map[i].rva_size;
		}
	}

	_virt_align = virt_align;
	_raw_align = raw_align;
}

uint32_t PEMap::GetRawAlign() const
{
	return _raw_align;
}

uint32_t PEMap::GetVirtualAlign() const
{
	return _virt_align;
}

/*
bool PEMap::ConvRvaToRaw(dword rva, PEBlockEntry& block)
{
	bool found = false;
	uint32_t diff;

	vector<PEMapEntry>& map = *this;
	for (uint32_t i = 0, count = map.size(); i < count; i++) {
		if (map[i].raw_size != 0 && rva >= map[i].rva && rva < map[i].rva + map[i].rva_size) {
			diff = rva - map[i].rva;
			if (diff >= map[i].raw_size) {
				continue;
			}

			block.offset   = map[i].raw + diff;
			block.size     = map[i].raw_size - diff;
			block.sect_num = map[i].sect_num;
			block.type     = map[i].type;

			found = true;
		}
	}

	return found;
}*/

bool PEMap::GetBlockInxByRva(dword rva, uint32_t& inx)
{
	bool found = false;

	vector<PEBlockEntry>& map = *this;
	for (uint32_t i = 0, count = map.size(); i < count; i++) {
		if (rva >= map[i].rva && rva < map[i].rva + map[i].rva_size) {
			inx = i;
			found = true;
			break;
		}
	}

	return found;
}

bool PEMap::GetRelativeBlockByRva(dword rva, PEBlockEntry& block)
{
	uint32_t inx;
	vector<PEBlockEntry>& map = *this;

	if (!GetBlockInxByRva(rva, inx)) {
		return false;
	}

	block = map[inx];

	uint32_t diff = rva - block.rva;
	if (diff >= block.raw_size) {
		block.raw_size = 0;
		block.raw = 0;
	} else {
		block.raw_size -= diff;
		block.raw += diff;
	}

	block.rva_size -= diff;
	block.rva = rva;

	return true;
}

/*
bool PEMap::ConvRawToRva(dword raw, std::vector<PEBlockEntry> &blocks)
{
	bool found = false;
	PEBlockEntry entry;
	uint32_t diff;

	blocks.clear();

	vector<PEMapEntry>& map = *this;
	for (uint32_t i = 0, count = map.size(); i < count; i++) {
		if (map[i].raw_size != 0 && raw >= map[i].raw && raw < map[i].raw + map[i].raw_size) {
			diff = raw - map[i].raw;

			entry.offset   = map[i].rva + diff;
			entry.size     = map[i].rva_size - diff;
			entry.sect_num = map[i].sect_num;
			entry.type     = map[i].type;

			blocks.push_back(entry);

			if (!found) {
				found = true;
			}
		}
	}

	return found;
}*/

bool PEMap::GetBlockInxByRaw(dword raw, vector<uint32_t> &inxs)
{
	bool found = false;
	PEBlockEntry entry;

	inxs.clear();

	vector<PEBlockEntry>& map = *this;
	for (uint32_t i = 0, count = map.size(); i < count; i++) {
		if (map[i].raw_size != 0 && raw >= map[i].raw && raw < map[i].raw + map[i].raw_size) {
			inxs.push_back(i);
			if (!found) {
				found = true;
			}
		}
	}

	return found;
}

bool PEMap::GetRelativeBlockByRaw(dword raw, vector<PEBlockEntry> &blocks)
{
	vector<uint32_t> inxs;

	if (!GetBlockInxByRaw(raw, inxs)) {
		return false;
	}

	blocks.clear();

	vector<PEBlockEntry>& map = *this;
	for (uint32_t i = 0, count = inxs.size(); i < count; i++) {
		blocks.push_back(map[inxs[i]]);
		uint32_t diff = raw - blocks[i].raw;
		blocks[i].raw_size -= diff;
		blocks[i].raw = raw;
		blocks[i].rva_size -= diff;
		blocks[i].rva += raw;
	}

	return true;
}

uint32_t PEMap::CalcVirtualSize()
{
	uint32_t peak = 0, temp_peak;

	vector<PEBlockEntry>& map = *this;
	for (uint32_t i = 0, count = map.size(); i < count; i++) {
		temp_peak = map[i].rva + map[i].rva_size;
		if (temp_peak > peak) {
			peak = temp_peak;
		}
	}

	return peak;
}

uint32_t PEMap::CalcRawSize()
{
	uint32_t peak = 0, temp_peak;

	vector<PEBlockEntry>& map = *this;
	for (uint32_t i = 0, count = map.size(); i < count; i++) {
		temp_peak = map[i].raw + map[i].raw_size;
		if (temp_peak > peak) {
			peak = temp_peak;
		}
	}

	return peak;
}

void PEMap::Align(dword &offset, uint32_t &size, uint32_t align, bool inc_align)
{//TODO
	dword align_offset;
	uint32_t align_size;

	if (inc_align) {
		align_offset = AlignmentToHigh(offset, align);
	} else {
		align_offset = AlignmentToLow(offset, align);
	}
	align_size = AlignmentToHigh(size, align);
	//align_offset = AlignmentToLow(offset, align);
	//align_size = AlignmentToHigh(size, align);

	if (offset + size > align_offset + align_size) {
		size += align;
	}

	offset = align_offset;
	size = align_size;
}

};//Monstra
