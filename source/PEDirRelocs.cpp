#include "PEDirRelocs.h"

namespace Monstra {

// ======================= PEDirRelocsParser =======================

PERelocsParser::PERelocsParser()
{
	Clear();
}

PERelocsParser::~PERelocsParser()
{
}

bool PERelocsParser::Parse(PESourceInterface* src, dword dir_rva, uint32_t dir_size, UAddress imgbase)
{
	uint32_t size = 0, blocks_count = 0;
	PEBuffer block;
	pPEImgBaseReloc prel;
	uint8_t* buf;

	Clear();

	if (!src->ConvRvaToPtr(block, dir_rva, dir_size)) {
		return SetError(E_UNKNOWN, __LINE__, "relocs: can't obtain buffer");
	}

	buf = reinterpret_cast<uint8_t*>(block.ptr());
	for (; size < dir_size; blocks_count++) {
		prel = (pPEImgBaseReloc)(buf + size);
		if (size + prel->SizeOfBlock > dir_size) {
			break;
		}
		size += prel->SizeOfBlock;
		if (prel->SizeOfBlock == 0) {
			break;
		}
	}

	_block_entry = block;

	_dir_offset = dir_rva;
	_dir_size = size;
	_blocks = blocks_count;
	_imgbase = imgbase;

	_parsed = true;

	return SetErrorOK;
}

void PERelocsParser::Clear()
{
	_dir_offset = 0;
	_dir_size = 0;
	_blocks = 0;
	_block_entry.empty();
	_imgbase = 0ull;
	_parsed = false;
}

bool PERelocsParser::IsParsed() const
{
	return _parsed;
}

PEBuffer& PERelocsParser::GetDir(dword* dir_rva)
{
	if (dir_rva != 0) {
		*dir_rva = _dir_offset;
	}
	return _block_entry;
}

const PEBuffer& PERelocsParser::GetDir(dword* dir_rva) const
{
	if (dir_rva != 0) {
		*dir_rva = _dir_offset;
	}
	return _block_entry;
}

uint32_t PERelocsParser::GetCountOfBlocks() const
{
	return _blocks;
}

UAddress PERelocsParser::GetImageBase() const
{
	return _imgbase;
}

bool PERelocsParser::EnumRelocs(enum_relocs_callback callback, void *params)
{
	if (!_parsed) {
		return false;
	}

	for (uint32_t i = 0, k = 0; ; k++) {
		pPEImgBaseReloc prel = (pPEImgBaseReloc)(_block_entry.ptr() + i);
		uint32_t offset = i;

		if (i + sizeof(PEImgBaseReloc) > _dir_size) {
			break;
		}

		i += prel->SizeOfBlock;
		if (prel->SizeOfBlock == 0 || i > _dir_size) {
			break;
		}
		if (i % 4 != 0) {
			i += 2;
		}

		PEBuffer rel_ptr;
		if (!rel_ptr.copy_range(_block_entry, _block_entry.offset() + offset, prel->SizeOfBlock)) {
			return false;
		}

		uint32_t count = prel->SizeOfBlock / sizeof(uint16_t);
		uint16_t* prels = (uint16_t*)prel;

		for (unsigned int a = 4; a < count; a++) {
			uint32_t type = prels[a] >> 12;
			if (!callback(rel_ptr, k, prel->VirtualAddress, type, 0x00000FFF & prels[a], params)) {
				return true;
			}
		}
	}

	return true;
}

bool PERelocsParser::EnumRelocs(enum_relocs_callback callback, void *params) const
{
	if (!_parsed) {
		return false;
	}

	for (uint32_t i = 0, k = 0; ; k++) {
		pPEImgBaseReloc prel = (pPEImgBaseReloc)(_block_entry.ptr() + i);
		uint32_t offset = i;

		if (i + sizeof(PEImgBaseReloc) > _dir_size) {
			break;
		}

		i += prel->SizeOfBlock;
		if (prel->SizeOfBlock == 0 || i > _dir_size) {
			break;
		}
		if (i % 4 != 0) {
			i += 2;
		}

		const PEBuffer rel_ptr(_block_entry, _block_entry.offset() + offset, prel->SizeOfBlock);

		uint32_t count = prel->SizeOfBlock / sizeof(uint16_t);
		uint16_t* prels = (uint16_t*)prel;

		for (unsigned int a = 4; a < count; a++) {
			uint32_t type = prels[a] >> 12;
			if (!callback(rel_ptr, k, prel->VirtualAddress, type, 0x00000FFF & prels[a], params)) {
				return true;
			}
		}
	}

	return true;
}

bool PERelocsParser::ChangeImagebase(PESourceInterface* src, UAddress new_base)
{
	return false;
}

uint32_t PERelocsParser::GetChecksum() const
{
	if (!_parsed) {
		return 0;
	}
	return checksum32ex(_block_entry.ptr(), _dir_size, 0);
}

// ======================= PEDirRelocs =======================

PERelocs::PERelocs()
{
}

PERelocs::~PERelocs()
{
}

struct RelocsEnumParams {
	PERelocs& pobj;
	uint32_t block_inx;
	RelocsEnumParams(PERelocs& p) : pobj(p), block_inx(-1) { }
};

bool PERelocs::Load(PERelocsParser &parser)
{
	Clear();

	if (!parser.IsParsed()) {
		return false;
	}

	if (!parser.EnumRelocs(enum_callback, &RelocsEnumParams(*this))) {
		return false;
	}

	return true;
}

void PERelocs::Clear()
{
	_imgbase = 0ull;
	clear();
}

UAddress PERelocs::GetImagebase() const
{
	return _imgbase;
}

void PERelocs::SetImagebase(UAddress imgbase)
{
	_imgbase = imgbase;
}

void PERelocs::Commit(void* buf, uint32_t size, UAddress new_base) const
{
	const vector<RelocsTable>& table = *this;

	//TODO
}

bool PERelocs::enum_callback(const PEBuffer block, uint32_t block_inx, 
	uint32_t block_base, word type, dword offset, void* params)
{
	RelocsEnumParams* param = reinterpret_cast<RelocsEnumParams*>(params);
	PERelocs& pobj = param->pobj;

	if (block_inx != param->block_inx) {
		pobj.push_back(RelocsTable(block_base));
		param->block_inx = block_inx;
	}

	pobj[block_inx].entry.push_back(RelocsTableEntry(type, offset));
	return true;
}
// ======================= PEDirRelocsBuilder =======================

};
