#include "PEHeader.h"
#include "PEMap.h"
#include "IOPointer.h"

using namespace std;

namespace Monstra {

// ======================= PEInfoHeader =======================

PEHeaderParser::PEHeaderParser()
{
}

PEHeaderParser::~PEHeaderParser()
{
}

bool PEHeaderParser::Parse(PESourceInterface* src)
{
	PEBuffer buf;
	uint32_t size, expect_size;
	uint8_t* data;
	uint32_t offset;
	//bool autosize;
	word *pmagic;

	Clear();

	if (!src->GetExpectedRvaBlock(buf, 0, MONSTRA_PE_HEADER_VIRTUAL_MAX_SIZE)) {
		return SetError(E_UNKNOWN, __LINE__, "header: can't obtain buffer");
	}

	size = buf.size();
	data = reinterpret_cast<uint8_t*>(buf.ptr());
	offset = 0;
	//autosize = (size == 0);

	if (!CalcHeaderSize(data, MONSTRA_PE_HEADER_VIRTUAL_MAX_SIZE, &expect_size)) {
		return SetError(E_UNKNOWN, __LINE__, "header: can't calc header size");
	}
	if (expect_size > size && !src->ConvRvaToPtr(buf, 0, expect_size)) {
		return SetError(E_UNKNOWN, __LINE__, "header: can't obtain expected buffer");
	}

	if (size < sizeof(PEImgDosHeader)) {
		return SetError(E_OUT_OF_RANGE, __LINE__, "header: header too small");
	}

	// Set dos header
	_pdos.copy_range(buf, 0);
	if (_pdos->e_magic != MONSTRA_PE_IMG_DOS_SIGNATURE) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "header: incorrect dos signature");
	}
	offset = _pdos->e_lfanew;

	if (size < offset + sizeof(dword) + sizeof(PEImgFileHeader)) {
		Clear();
		return SetError(E_OUT_OF_RANGE, __LINE__, "header: header too small");
	}

	if (*(dword *)(data + offset) != MONSTRA_PE_IMG_NT_SIGNATURE) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "header: incorrect pe signature");
	}
	offset += sizeof(dword);

	// Set PE header
	_pimg.copy_range(buf, offset);
	//_pimg = PEImgFileHeader_ptr(data + offset);
	offset += sizeof(PEImgFileHeader);
	_sect_count = _pimg->NumberOfSections;

	// Detect PE architecture
	pmagic = (word *)(data + offset);
	switch (*pmagic) {
	case MONSTRA_PE_IMG_NT_OPTIONAL_HDR32_MAGIC:
		_arch = PE_32;
		break;
	case MONSTRA_PE_IMG_NT_OPTIONAL_HDR64_MAGIC:
		_arch = PE_64;
		break;
	default:
		_arch = PE_UNK;
	}

	if (_arch == PE_UNK) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "header: unknown architecture");
	}

	// Set PE optional header
	if (GetArch() == PE_32) {
		if (size < offset + sizeof(PEImgOptHeader32)) {
			Clear();
			return SetError(E_OUT_OF_RANGE, __LINE__, "header: header too small");
		}

		_pheader32.copy_range(buf, _pdos->e_lfanew);
		_popt32.copy_range(buf, offset);

		_pdir.copy_range(buf, _popt32.offset() + MONSTRA_PE_IMG_DATADIR_OPT32_OFFSET,
			sizeof(PEImgDataDir) * MONSTRA_PE_IMG_DIR_ENTRIES);

		_virt_align = _popt32->SectionAlignment;
		_raw_align = _popt32->FileAlignment;
	} else if (GetArch() == PE_64) {
		if (size < offset + sizeof(PEImgOptHeader64)) {
			Clear();
			return SetError(E_OUT_OF_RANGE, __LINE__, "header: header too small");
		}

		_pheader64.copy_range(buf, _pdos->e_lfanew);
		_popt64.copy_range(buf, offset);

		_pdir.copy_range(buf, _popt64.offset() + MONSTRA_PE_IMG_DATADIR_OPT64_OFFSET, MONSTRA_PE_IMG_DIR_ENTRIES);

		_virt_align = _popt64->SectionAlignment;
		_raw_align = _popt64->FileAlignment;
	}

	// Check alignment
	if (!CheckSquare(_virt_align) || !CheckSquare(_raw_align)) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "header: invalid alignment");
	}

	// Set PE sections
	if (_sect_count > 0) {
		_psects.copy_range(buf, offset + _pimg->SizeOfOptionalHeader, _sect_count);
		offset += _pimg->SizeOfOptionalHeader + _psects.size();
		if (size < offset) {
			Clear();
			return SetError(E_OUT_OF_RANGE, __LINE__, "header: section info out of range");
		}
	}

	_header_size = offset;
	if (_arch == PE_32) {
		_header_size = (_header_size < _popt32->SizeOfHeaders ? _popt32->SizeOfHeaders : _header_size);
	} else {
		_header_size = (_header_size < _popt64->SizeOfHeaders ? _popt64->SizeOfHeaders : _header_size);
	}

	_is_parsed = true;
	return SetErrorOK;
}

void PEHeaderParser::Clear()
{
	_is_parsed      = false;
	_arch           = PE_UNK;

	_sect_count     = 0;
	_header_size    = 0;
	_virt_align     = 0;
	_raw_align      = 0;

	_pdos.empty();
	_pimg.empty();
	_popt32.empty();
	_popt64.empty();
	_pheader32.empty();
	_pheader64.empty();
	_pdir.empty();
	_psects.empty();
}

bool PEHeaderParser::CalcHeaderSize(void *buffer, unsigned int size, unsigned int *pheader_size)
{
	pPEImgDosHeader     pdos;
	pPEImgFileHeader    pimg;
	uint8_t *data = (uint8_t *)buffer;
	unsigned int sect_offset, sect_size, opt_size;
	word *pmagic;

	if (size < sizeof(PEImgDosHeader)) {
		return false;
	}

	pdos = (pPEImgDosHeader)data;
	if (pdos->e_magic != MONSTRA_PE_IMG_DOS_SIGNATURE) {
		return false;
	}

	if (size < pdos->e_lfanew + sizeof(dword) + sizeof(PEImgFileHeader) + sizeof(word)) {
		return false;
	}

	if (*(dword *)(data + pdos->e_lfanew) != MONSTRA_PE_IMG_NT_SIGNATURE) {
		return false;
	}

	pimg = (pPEImgFileHeader)(data + pdos->e_lfanew + sizeof(dword));
	pmagic = (word *)(data + pdos->e_lfanew + sizeof(dword) + sizeof(PEImgFileHeader));

	sect_offset = pimg->SizeOfOptionalHeader;

	switch (*pmagic) {
	case MONSTRA_PE_IMG_NT_OPTIONAL_HDR32_MAGIC:
		opt_size = sizeof(PEImgOptHeader32);
		break;
	case MONSTRA_PE_IMG_NT_OPTIONAL_HDR64_MAGIC:
		opt_size = sizeof(PEImgOptHeader64);
		break;
	default:
		return false;
	}

	*pheader_size = pdos->e_lfanew + sizeof(dword) + sizeof(PEImgFileHeader);

	sect_size = (pimg->NumberOfSections * sizeof(PEImgSectionHeader));
	if (sect_offset + sect_size < opt_size) {
		*pheader_size += opt_size;
	} else {
		*pheader_size += sect_offset + sect_size;
	}

	return true;
}

bool PEHeaderParser::IsParsed() const
{
	return _is_parsed;
}

bool PEHeaderParser::ParseMap(PEMap& pemap)
{
	if (!_is_parsed) {
		return SetError(E_NOT_FOUND, __LINE__, "header: isn't parsed");
	}
	if (!pemap.Load(*this, _virt_align, _raw_align)) {
		return SetError(E_UNKNOWN, __LINE__, "header: can't parse map");
	}
	return SetErrorOK;
}

PEArchitecture PEHeaderParser::GetArch() const
{
	return _arch;
}

PEImgDosHeader_ptr& PEHeaderParser::GetDos()
{
	return _pdos;
}

PEImgFileHeader_ptr& PEHeaderParser::GetImg()
{
	return _pimg;
}

PEImgOptHeader32_ptr& PEHeaderParser::GetOpt32()
{
	return _popt32;
}

PEImgOptHeader64_ptr& PEHeaderParser::GetOpt64()
{
	return _popt64;
}

PEImgDataDir_ptr& PEHeaderParser::GetDataDir()
{
	return _pdir;
}

PEImgNtHeaders32_ptr& PEHeaderParser::GetHeader32()
{
	return _pheader32;
}

PEImgNtHeaders64_ptr& PEHeaderParser::GetHeader64()
{
	return _pheader64;
}

PEImgSectionHeader_ptr& PEHeaderParser::GetSectors()
{
	return _psects;
}

/*
PEImgSectionHeader_ptr& PEHeaderParser::GetSectorByPos(unsigned short pos)
{
	if (pos >= _sect_count) {
		return 0;
	}
	return _psects[pos];
}*/

bool PEHeaderParser::HaveDataDir(uint32_t num)
{
	if (!_is_parsed || num >= MONSTRA_PE_IMG_DIR_ENTRIES) {
		return false;
	}
	return (_pdir[num].VirtualAddress != 0);
	//return 0;
}

int PEHeaderParser::FindFirstSectorPosByName(char *pname)
{
	char buf[MONSTRA_PE_IMG_SHORT_NAME_LEN + 1] = {};

	if (!_is_parsed) {
		return MONSTRA_PE_INVALID_SECTOR;
	}

	for (unsigned int i = 0; i < _sect_count; i++) {
		memcpy(buf, _psects[i].Name, MONSTRA_PE_IMG_SHORT_NAME_LEN);
		if (!strcmp(buf, pname)) {
			return i;
		}
	}

	return MONSTRA_PE_INVALID_SECTOR;
}

int PEHeaderParser::FindFirstSectorPosByRaw(dword roffset)
{//TOTEST
	if (!_is_parsed) {
		return MONSTRA_PE_INVALID_SECTOR;
	}

	for (int i = 0; i < _sect_count; i++) {
		uint32_t raw_ptr = AlignmentToLow(_psects[i].PointerToRawData, _raw_align);
		if (raw_ptr > roffset) {
			break;
		}

		if (roffset < AlignmentToHigh(_psects[i].PointerToRawData + _psects[i].SizeOfRawData, _raw_align)
		|| _psects[i].SizeOfRawData == 0) {
			return i;
		}
	}

	return MONSTRA_PE_INVALID_SECTOR;
}

int PEHeaderParser::FindSectorPosByVirtual(dword voffset)
{//TOTEST
	if (!_is_parsed) {
		return MONSTRA_PE_INVALID_SECTOR;
	}

	int num = MONSTRA_PE_INVALID_SECTOR;

	for (unsigned int i = 0; i < _sect_count; i++) {
		uint32_t sector_vsize;

		//check offset
		if (_psects[i].VirtualAddress > voffset) {
			continue;
		}

		//check size
		if (_psects[i].Misc.VirtualSize == 0) {
			if (_psects[i].PointerToRawData == 0) {// section is empty
				continue;
			}
			sector_vsize = AlignmentToHigh(_psects[i].SizeOfRawData, _virt_align);;
		} else {
			sector_vsize = AlignmentToHigh(_psects[i].Misc.VirtualSize, _virt_align);
		}

		if (/*_psects[i].VirtualAddress <= voffset && */_psects[i].VirtualAddress + sector_vsize > voffset) {
			if (_psects[i].SizeOfRawData == 0) {
				num = i;
				continue;
			}
			return i;
		}
	}

	return num;
}

bool PEHeaderParser::FindSectorPosByName(char *pname, std::vector<int> &positions)
{
	char buf[MONSTRA_PE_IMG_SHORT_NAME_LEN + 1] = {};

	if (!_is_parsed) {
		return false;
	}

	positions.clear();

	for (unsigned int i = 0; i < _sect_count; i++) {
		memcpy(buf, _psects[i].Name, MONSTRA_PE_IMG_SHORT_NAME_LEN);
		if (!strcmp(buf, pname)) {
			positions.push_back(i);
		}
	}

	return true;
}

bool PEHeaderParser::FindSectorPosByRaw(dword roffset, std::vector<int> &positions)
{//TOTEST
	if (!_is_parsed) {
		return false;
	}

	positions.clear();

	for (int i = 0; i < _sect_count; i++) {
		uint32_t raw_ptr = AlignmentToLow(_psects[i].PointerToRawData, _raw_align);
		if (raw_ptr > roffset) {
			continue;;
		}

		if (_psects[i].SizeOfRawData == 0 
		|| roffset < raw_ptr + AlignmentToHigh(_psects[i].SizeOfRawData, _raw_align)) {
			positions.push_back(i);
		}
	}

	return true;
}

uint32_t PEHeaderParser::GetVirtualAlignment() const
{
	return _virt_align;
}

uint32_t PEHeaderParser::GetRawAlignment() const
{
	return _raw_align;
}

uint32_t PEHeaderParser::GetHeaderSize() const
{
	return _header_size;
}

};//Monstra

/*
namespace Monstra {

// ======================= PEInfoHeader =======================

PEHeaderParser::PEHeaderParser()
{
	Clear();
}

PEHeaderParser::~PEHeaderParser()
{
}

bool PEHeaderParser::Parse(void *buffer, unsigned int size)
{
	uint8_t *data = (uint8_t *)buffer;
	uint32_t offset = 0;
	bool autosize = (size == 0);
	word *pmagic;

	Clear();

	if (autosize && !CalcHeaderSize(buffer, MONSTRA_PE_HEADER_VIRTUAL_MAX_SIZE, &size)) {
		return SetError(E_UNKNOWN, __LINE__, "parse: can't calc header size");
	}

	if (size < sizeof(PEImgDosHeader)) {
		return SetError(E_OUT_OF_RANGE, __LINE__, "parse: header too small");
	}

	// Set dos header
	_pdos = (pPEImgDosHeader)data;
	if (_pdos->e_magic != MONSTRA_PE_IMG_DOS_SIGNATURE) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "parse: incorrect dos signature");
	}
	offset = _pdos->e_lfanew;

	if (size < offset + sizeof(dword) + sizeof(PEImgFileHeader)) {
		Clear();
		return SetError(E_OUT_OF_RANGE, __LINE__, "parse: header too small");
	}

	if (*(dword *)(data + offset) != MONSTRA_PE_IMG_NT_SIGNATURE) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "parse: incorrect pe signature");
	}
	offset += sizeof(dword);

	// Set PE header
	_pimg = (pPEImgFileHeader)(data + offset);
	offset += sizeof(PEImgFileHeader);
	_sect_count = _pimg->NumberOfSections;

	// Detect PE architecture
	pmagic = (word *)(data + offset);
	switch (*pmagic) {
	case MONSTRA_PE_IMG_NT_OPTIONAL_HDR32_MAGIC:
		_arch = PE_32;
		break;
	case MONSTRA_PE_IMG_NT_OPTIONAL_HDR64_MAGIC:
		_arch = PE_64;
		break;
	default:
		_arch = PE_UNK;
	}

	if (_arch == PE_UNK) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "parse: unknown architecture");
	}

	// Set PE optional header
	if (GetArch() == PE_32) {
		if (size < offset + sizeof(PEImgOptHeader32)) {
			Clear();
			return SetError(E_OUT_OF_RANGE, __LINE__, "parse: header too small");
		}

		_pheader32 = (pPEImgNtHeaders32)(data + _pdos->e_lfanew);
		_pheader64 = 0;

		_popt32 = (pPEImgOptHeader32)(data + offset);
		_popt64 = 0;

		_pdir = _popt32->DataDirectory;

		_virt_align = _popt32->SectionAlignment;
		_raw_align = _popt32->FileAlignment;
	} else if (GetArch() == PE_64) {
		if (size < offset + sizeof(PEImgOptHeader64)) {
			Clear();
			return SetError(E_OUT_OF_RANGE, __LINE__, "parse: header too small");
		}

		_pheader32 = 0;
		_pheader64 = (pPEImgNtHeaders64)(data + _pdos->e_lfanew);

		_popt32 = 0;
		_popt64 = (pPEImgOptHeader64)(data + offset);

		_pdir = _popt64->DataDirectory;

		_virt_align = _popt64->SectionAlignment;
		_raw_align = _popt64->FileAlignment;
	}

	// Check alignment
	if (!CheckSquare(_virt_align) || !CheckSquare(_raw_align)) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "parse: invalid alignment");
	}

	// Set PE sections
	if (_sect_count > 0) {
		_psects = (pPEImgSectionHeader)(data + offset + _pimg->SizeOfOptionalHeader);
		offset += _pimg->SizeOfOptionalHeader + (sizeof(PEImgSectionHeader) * _sect_count);
		if (size < offset) {
			Clear();
			return SetError(E_OUT_OF_RANGE, __LINE__, "parse: section info out of range");
		}
	} else {
		_psects = NULL;
	}

	_header_size = offset;
	if (_arch == PE_32) {
		_header_size = (_header_size < _popt32->SizeOfHeaders ? _popt32->SizeOfHeaders : _header_size);
	} else {
		_header_size = (_header_size < _popt64->SizeOfHeaders ? _popt64->SizeOfHeaders : _header_size);
	}

	_is_parsed = true;
	return SetErrorOK;
}

void PEHeaderParser::Clear()
{
	_is_parsed      = false;
	_arch           = PE_UNK;

	_pdos           = 0;
	_pimg           = 0;
	_popt32         = 0;
	_popt64         = 0;
	_pdir           = 0;
	_pheader32      = 0;
	_pheader64      = 0;
	_psects         = 0;
	_sect_count     = 0;

	_header_size    = 0;

	_virt_align     = 0;
	_raw_align      = 0;
}

bool PEHeaderParser::IsParsed() const
{
	return _is_parsed;
}

bool PEHeaderParser::ParseMap(void *pemap)
{
	return SetErrorOK;
}

PEArchitecture PEHeaderParser::GetArch() const
{
	return _arch;
}

pPEImgDosHeader PEHeaderParser::GetDos() const
{
	return _pdos;
}

pPEImgFileHeader PEHeaderParser::GetImg() const
{
	return _pimg;
}

pPEImgOptHeader32 PEHeaderParser::GetOpt32() const
{
	return _popt32;
}

pPEImgOptHeader64 PEHeaderParser::GetOpt64() const
{
	return _popt64;
}

pPEImgDataDir PEHeaderParser::GetDataDir() const
{
	return _pdir;
}

pPEImgNtHeaders32 PEHeaderParser::GetHeader32() const
{
	return _pheader32;
}

pPEImgNtHeaders64 PEHeaderParser::GetHeader64() const
{
	return _pheader64;
}

pPEImgSectionHeader PEHeaderParser::GetSectors(unsigned short *pcount) const
{
	if (pcount != 0) {
		*pcount = _sect_count;
	}
	return _psects;
}

pPEImgSectionHeader PEHeaderParser::GetSectorByPos(unsigned short pos) const
{
	if (pos >= _sect_count) {
		return 0;
	}
	return &_psects[pos];
}

bool PEHeaderParser::HaveDataDir(unsigned int num) const
{
	if (!_is_parsed || num >= MONSTRA_PE_IMG_DIR_ENTRIES) {
		return false;
	}
	return (_pdir[num].VirtualAddress != 0);
}

int PEHeaderParser::FindFirstSectorPosByName(char *pname)
{
	char buf[MONSTRA_PE_IMG_SHORT_NAME_LEN + 1] = {};

	if (!_is_parsed) {
		return MONSTRA_PE_INVALID_SECTOR;
	}

	for (unsigned int i = 0; i < _sect_count; i++) {
		memcpy(buf, _psects[i].Name, MONSTRA_PE_IMG_SHORT_NAME_LEN);
		if (!strcmp(buf, pname)) {
			return i;
		}
	}

	return MONSTRA_PE_INVALID_SECTOR;
}

int PEHeaderParser::FindFirstSectorPosByRaw(dword roffset)
{//TOTEST
	if (!_is_parsed) {
		return MONSTRA_PE_INVALID_SECTOR;
	}

	for (int i = 0; i < _sect_count; i++) {
		uint32_t raw_ptr = AlignmentToLow(_psects[i].PointerToRawData, _raw_align);
		if (raw_ptr > roffset) {
			break;
		}

		if (roffset < AlignmentToHigh(_psects[i].PointerToRawData + _psects[i].SizeOfRawData, _raw_align)
		|| _psects[i].SizeOfRawData == 0) {
			return i;
		}
	}

	return MONSTRA_PE_INVALID_SECTOR;
}

int PEHeaderParser::FindSectorPosByVirtual(dword voffset)
{//TOTEST
	if (!_is_parsed) {
		return MONSTRA_PE_INVALID_SECTOR;
	}

	int num = MONSTRA_PE_INVALID_SECTOR;

	for (unsigned int i = 0; i < _sect_count; i++) {
		uint32_t sector_vsize;

		//check offset
		if (_psects[i].VirtualAddress > voffset) {
			continue;
		}

		//check size
		if (_psects[i].Misc.VirtualSize == 0) {
			if (_psects[i].PointerToRawData == 0) {// section is empty
				continue;
			}
			sector_vsize = AlignmentToHigh(_psects[i].SizeOfRawData, _virt_align);;
		} else {
			sector_vsize = AlignmentToHigh(_psects[i].Misc.VirtualSize, _virt_align);
		}

		if (/ *_psects[i].VirtualAddress <= voffset && * /_psects[i].VirtualAddress + sector_vsize > voffset) {
			if (_psects[i].SizeOfRawData == 0) {
				num = i;
				continue;
			}
			return i;
		}
	}

	return num;
}

bool PEHeaderParser::FindSectorPosByName(char *pname, std::vector<int> &positions)
{
	char buf[MONSTRA_PE_IMG_SHORT_NAME_LEN + 1] = {};

	if (!_is_parsed) {
		return false;
	}

	positions.clear();

	for (unsigned int i = 0; i < _sect_count; i++) {
		memcpy(buf, _psects[i].Name, MONSTRA_PE_IMG_SHORT_NAME_LEN);
		if (!strcmp(buf, pname)) {
			positions.push_back(i);
		}
	}

	return true;
}

bool PEHeaderParser::FindSectorPosByRaw(dword roffset, std::vector<int> &positions)
{//TOTEST
	if (!_is_parsed) {
		return false;
	}

	positions.clear();

	for (int i = 0; i < _sect_count; i++) {
		uint32_t raw_ptr = AlignmentToLow(_psects[i].PointerToRawData, _raw_align);
		if (raw_ptr > roffset) {
			continue;;
		}

		if (_psects[i].SizeOfRawData == 0 
		|| roffset < raw_ptr + AlignmentToHigh(_psects[i].SizeOfRawData, _raw_align)) {
			positions.push_back(i);
		}
	}

	return true;
}

uint32_t PEHeaderParser::GetVirtualAlignment() const
{
	return _virt_align;
}

uint32_t PEHeaderParser::GetRawAlignment() const
{
	return _raw_align;
}

uint32_t PEHeaderParser::GetHeaderSize() const
{
	return _header_size;
}

bool PEHeaderParser::CalcHeaderSize(void *buffer, unsigned int size, unsigned int *pheader_size)
{
	pPEImgDosHeader     pdos;
	pPEImgFileHeader    pimg;
	uint8_t *data = (uint8_t *)buffer;
	unsigned int sect_offset, sect_size, opt_size;
	word *pmagic;

	if (size < sizeof(PEImgDosHeader)) {
		return false;
	}

	pdos = (pPEImgDosHeader)data;
	if (pdos->e_magic != MONSTRA_PE_IMG_DOS_SIGNATURE) {
		return false;
	}

	if (size < pdos->e_lfanew + sizeof(dword) + sizeof(PEImgFileHeader) + sizeof(word)) {
		return false;
	}

	if (*(dword *)(data + pdos->e_lfanew) != MONSTRA_PE_IMG_NT_SIGNATURE) {
		return false;
	}

	pimg = (pPEImgFileHeader)(data + pdos->e_lfanew + sizeof(dword));
	pmagic = (word *)(data + pdos->e_lfanew + sizeof(dword) + sizeof(PEImgFileHeader));

	sect_offset = pimg->SizeOfOptionalHeader;

	switch (*pmagic) {
	case MONSTRA_PE_IMG_NT_OPTIONAL_HDR32_MAGIC:
		opt_size = sizeof(PEImgOptHeader32);
		break;
	case MONSTRA_PE_IMG_NT_OPTIONAL_HDR64_MAGIC:
		opt_size = sizeof(PEImgOptHeader64);
		break;
	default:
		return false;
	}

	*pheader_size = pdos->e_lfanew + sizeof(dword) + sizeof(PEImgFileHeader);

	sect_size = (pimg->NumberOfSections * sizeof(PEImgSectionHeader));
	if (sect_offset + sect_size < opt_size) {
		*pheader_size += opt_size;
	} else {
		*pheader_size += sect_offset + sect_size;
	}

	return true;
}

// ======================= PEHeader =======================

PEHeader::PEHeader()
{
	Create(PE_32);
}

PEHeader::~PEHeader()
{
}

bool PEHeader::Create(PEArchitecture arch)
{
	memset(&_dos, 0, sizeof(_dos));
	memset(&_header32, 0, sizeof(_header32));
	memset(&_header64, 0, sizeof(_header64));

	_dos.e_magic = MONSTRA_PE_IMG_DOS_SIGNATURE;

	if (arch == PE_32) {
		_arch = arch;
		_header32.Signature = MONSTRA_PE_IMG_NT_SIGNATURE;
		_header32.FileHeader.Machine = MONSTRA_PE_IMG_FILE_MACHINE_I386;
		_header32.OptionalHeader.Magic = MONSTRA_PE_IMG_NT_OPTIONAL_HDR32_MAGIC;
		_pimg = &_header32.FileHeader;
	} else if (arch == PE_64) {
		_arch = arch;
		_header64.Signature = MONSTRA_PE_IMG_NT_SIGNATURE;
		_header64.FileHeader.Machine = MONSTRA_PE_IMG_FILE_MACHINE_AMD64;
		_header64.OptionalHeader.Magic = MONSTRA_PE_IMG_NT_OPTIONAL_HDR64_MAGIC;
		_pimg = &_header64.FileHeader;
	} else {
		return false;
	}

	return true;
}

bool PEHeader::Load(PEHeaderParser &peinfo)
{
	pPEImgDosHeader pdos;

	if (!peinfo.IsParsed()) {
		return false;
	}

	_arch = peinfo.GetArch();
	pdos = peinfo.GetDos();

	if (_arch == PE_32) {
		memcpy(&_header32, peinfo.GetHeader32(), sizeof(_header32));
		memset(&_header64, 0, sizeof(_header64));
		_pimg = &_header32.FileHeader;
	} else if (_arch == PE_64) {
		memcpy(&_header64, peinfo.GetHeader64(), sizeof(_header64));
		memset(&_header32, 0, sizeof(_header32));
		_pimg = &_header64.FileHeader;
	} else {
		return false;
	}

	return true;
}

bool PEHeader::IsValid()
{//TODO
	return false;
}

PEArchitecture PEHeader::GetArch() const
{
	return _arch;
}

pPEImgDosHeader PEHeader::GetDos()
{
	return &_dos;
}

pPEImgFileHeader PEHeader::GetImg()
{
	return _pimg;
}

pPEImgNtHeaders32 PEHeader::GetHeader32()
{
	if (_arch != PE_32) {
		return 0;
	}
	return &_header32;
}

pPEImgNtHeaders64 PEHeader::GetHeader64()
{
	if (_arch != PE_64) {
		return 0;
	}
	return &_header64;
}

uint16_t PEHeader::GetMachine() const
{
	return _pimg->Machine;
}

void PEHeader::SetMachine(uint16_t machine)
{
	_pimg->Machine = machine;
}

uint16_t PEHeader::GetCharacteristics() const
{
	return _pimg->Characteristics;
}

void PEHeader::SetCharacteristics(uint16_t chcs)
{
	_pimg->Characteristics = chcs;
}

uint32_t PEHeader::GetVirtualAlignment() const
{
	uint32_t align;
	if (_arch == PE_32) {
		align = _header32.OptionalHeader.SectionAlignment;
	} else {
		align = _header64.OptionalHeader.SectionAlignment;
	}
	return align;
}

void PEHeader::SetVirtualAlignment(uint32_t valign)
{
	if (_arch == PE_32) {
		_header32.OptionalHeader.SectionAlignment = valign;
	} else {
		_header64.OptionalHeader.SectionAlignment = valign;
	}
}

uint32_t PEHeader::GetRawAlignment() const
{
	uint32_t align;
	if (_arch == PE_32) {
		align = _header32.OptionalHeader.FileAlignment;
	} else {
		align = _header64.OptionalHeader.FileAlignment;
	}
	return align;
}

void PEHeader::SetRawAlignment(uint32_t ralign)
{
	if (_arch == PE_32) {
		_header32.OptionalHeader.FileAlignment = ralign;
	} else {
		_header64.OptionalHeader.FileAlignment = ralign;
	}
}

uint16_t PEHeader::GetSubsystem() const
{
	uint32_t subsys;
	if (_arch == PE_32) {
		subsys = _header32.OptionalHeader.Subsystem;
	} else {
		subsys = _header64.OptionalHeader.Subsystem;
	}
	return subsys;
}

void PEHeader::SetSubsystem(uint16_t subsys)
{
	if (_arch == PE_32) {
		_header32.OptionalHeader.Subsystem = subsys;
	} else {
		_header64.OptionalHeader.Subsystem = subsys;
	}
}

uint32_t PEHeader::GetEntryPoint() const
{
	uint32_t ep;
	if (_arch == PE_32) {
		ep = _header32.OptionalHeader.AddressOfEntryPoint;
	} else {
		ep = _header64.OptionalHeader.AddressOfEntryPoint;
	}
	return ep;
}

void PEHeader::SetEntryPoint(uint32_t ep)
{
	if (_arch == PE_32) {
		_header32.OptionalHeader.AddressOfEntryPoint = ep;
	} else {
		_header64.OptionalHeader.AddressOfEntryPoint = ep;
	}
}

UAddress PEHeader::GetImageBase() const
{
	UAddress addr = 0ull;
	if (_arch == PE_32) {
		addr = _header32.OptionalHeader.ImageBase;
	} else {
		addr = _header64.OptionalHeader.ImageBase;
	}
	return addr;
}

void PEHeader::SetImageBase(UAddress addr)
{
	if (_arch == PE_32) {
		_header32.OptionalHeader.ImageBase = addr;
	} else {
		_header64.OptionalHeader.ImageBase = addr;
	}
}

// ======================= PEHeaderBuilder =======================



};/ *Monstra namespace* /*/