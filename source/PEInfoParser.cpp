#include "PEInfoParser.h"
#include "PEHeader.h"
#include "PESections.h"
#include "PEDirRelocs.h"
#include <exception>
#include <algorithm>

using namespace std;

namespace Monstra {

// ======================= PEParser =======================

PEParser::PEParser() : _parsed(false)
{
}

bool PEParser::ParseHeader(PEHeaderParser &parser)
{
	if (!_parsed) {
		return SetError(E_NOT_FOUND, __LINE__, "parser: isn't parsed");
	}
	if (!parser.Parse(this)) {
		return InheritErrorFrom(parser);
	}
	return SetErrorOK;
}

bool PEParser::ParseHeader(PEHeader &header)
{
	PEHeaderParser parser;
	if (!_parsed) {
		return SetError(E_NOT_FOUND, __LINE__, "parser: isn't parsed");
	}
	if (!ParseHeader(parser)) {
		return SetErrorInherit;
	}
	if (!header.Load(parser)) {
		return SetError(E_UNKNOWN, __LINE__, "parser: can't load header");
	}
	return SetErrorOK;
}

bool PEParser::ParseSections(PESections &sections)
{
	PEHeaderParser parser;
	if (!_parsed) {
		return SetError(E_NOT_FOUND, __LINE__, "parser: isn't parsed");
	}
	if (!ParseHeader(parser)) {
		return SetErrorInherit;
	}
	if (!sections.Load(parser)) {
		return SetError(E_UNKNOWN, __LINE__, "parser: can't load header");
	}
	return SetErrorOK;
}

bool PEParser::ParseRelocs(PERelocsParser& parser)
{
	if (!_parsed) {
		return SetError(E_NOT_FOUND, __LINE__, "parser: isn't parsed");
	}
	if (!_header.HaveDataDir(MONSTRA_PE_IMG_DIR_ENTRY_BASERELOC)) {
		return SetError(E_NOT_FOUND, __LINE__, "parser: relocs dir not found");
	}
	if (!parser.Parse(this, _header.GetDataDir()[MONSTRA_PE_IMG_DIR_ENTRY_BASERELOC].VirtualAddress,
		_header.GetDataDir()[MONSTRA_PE_IMG_DIR_ENTRY_BASERELOC].Size, 
		_header.GetArch() == PE_32 ? _header.GetOpt32()->ImageBase : _header.GetOpt64()->ImageBase)) {
		return InheritErrorFrom(parser);
	}
	return SetErrorOK;
}

bool PEParser::ParseRelocs(PERelocs &relocs)
{
	PERelocsParser parser;
	if (!_parsed) {
		return SetError(E_NOT_FOUND, __LINE__, "parser: isn't parsed");
	}
	if (!ParseRelocs(parser)) {
		return SetErrorInherit;
	}
	if (!relocs.Load(parser)) {
		return SetError(E_UNKNOWN, __LINE__, "parser: can't load relocs");
	}
	return SetErrorOK;
}


// ======================= PEBufferInterface =======================

PEBufferMapped::PEBufferMapped() :
	_conv_inx(0),
	_expected_inx(0),
	_buf(0),
	_buf_size(0)
{
}

PEBufferMapped::PEBufferMapped(void* buf, uint32_t size) :
	_conv_inx(0),
	_expected_inx(0)
{
	if (buf == 0) {
		throw exception("parser: invalid buffer ptr");
	}

	_buf = reinterpret_cast<uint8_t*>(buf);
	_buf_size = size;

	Parse();
}

PEBufferMapped::~PEBufferMapped()
{
}

bool PEBufferMapped::Parse(void* buf, uint32_t size)
{
	Clear();

	if (buf == 0 && _buf == 0) {
		return SetError(E_UNKNOWN, __LINE__, "parser: invalid params");
	}
	if (buf != 0) {
		_buf = reinterpret_cast<uint8_t*>(buf);
		_buf_size = size;
	}

	if (_buf_size == 0 && !PEHeaderParser::CalcHeaderSize(_buf, MONSTRA_PE_HEADER_VIRTUAL_MAX_SIZE, &_buf_size)) {
		return SetError(E_UNKNOWN, __LINE__, "parser: can't calculate header size");
	}

	if (!_header.Parse(this)) {
		return InheritErrorFrom(_header);
	}

	if (!_map.Load(_header)) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "parser: can't load pe map");
	}

	_parsed = true;
	return SetErrorOK;
}

void PEBufferMapped::Clear()
{
	_header.Clear();
	_map.Clear();

	_conv_blocks.clear();
	_expected_blocks.clear();

	_parsed = false;
}

bool PEBufferMapped::IsParsed() const
{
	return _parsed;
}

PEHeaderParser& PEBufferMapped::GetHeader()
{
	return _header;
}

bool PEBufferMapped::GetMap(PEMap &pemap) const
{
	if (!_parsed) {
		return false;
	}
	pemap = _map;
	return true;
}

bool PEBufferMapped::SetMap(PEMap &pemap)
{
	if (!_parsed) {
		return false;
	}
	_map = pemap;
	return true;
}

bool PEBufferMapped::ConvRawToPtr(io_ptr_interface& ptr, dword raw, uint32_t size)
{
	if (_buf == 0) {
		return false;
	}

	if (!_parsed) {// if called before parsing
		if (raw + size > _buf_size) {
			return false;
		}
		ptr = PEBuffer(_buf + raw, raw, size);
		return true;
	}

	if (!_map.GetRelativeBlockByRaw(raw, _conv_blocks)) {
		return false;
	}

	_conv_inx = 0;
	_conv_size = size;

	return NextRawToPtr(ptr);
}

bool PEBufferMapped::NextRawToPtr(io_ptr_interface& ptr)
{
	dword voffset;
	vector<PEBlockEntry>& blocks = _conv_blocks;

	if (!_parsed) {
		return false;
	}

	bool found = false;
	for (uint32_t i = _conv_inx, count = blocks.size(); i < count; i++, _conv_inx++) {
		if (blocks[i].raw_size < _conv_size) {
			continue;
		}
		if (blocks[i].rva_size >= _conv_size && blocks[i].rva + _conv_size <= _buf_size) {
			voffset = blocks[i].rva;
			_conv_inx++;
			found = true;
			break;
		}
	}
	if (!found) {
		return false;
	}

	ptr = PEBuffer(_buf + voffset, voffset, _conv_size);
	return true;
}

bool PEBufferMapped::ConvRvaToPtr(io_ptr_interface& ptr, dword rva, uint32_t size)
{
	PEBlockEntry entry;

	if (_buf == 0) {
		return false;
	}

	if (rva + size > _buf_size) {
		return false;
	}

	if (!_parsed) {// if called before parsing
		ptr = PEBuffer(_buf + rva, rva, size);
		return true;
	}

	if (!_map.GetRelativeBlockByRva(rva, entry)) {
		return false;
	}

	if (entry.rva + entry.rva_size < rva + size) {
		return false;
	}

	ptr = PEBuffer(_buf + rva, rva, size);
	return true;
}

bool PEBufferMapped::GetExpectedRawBlock(io_ptr_interface& ptr, dword raw, uint32_t expected_size)
{
	if (_buf == 0) {
		return false;
	}

	if (!_parsed) {// if called before parsing
		if (raw >= _buf_size) {
			return false;
		}
		uint32_t peak = _buf_size - raw;
		ptr = PEBuffer(_buf + raw, raw, peak < expected_size ? peak : expected_size);
		return true;
	}

	vector<uint32_t> inxs;
	if (!_map.GetBlockInxByRaw(raw, inxs)) {
		return false;
	}

	_expected_blocks.clear();
	for (uint32_t i = 0, count = inxs.size(); i < count; i++) {
		_expected_blocks.push_back(_map[ inxs[i] ]);
	}

	_expected_inx = 0;
	_expected_raw = raw;
	_expected_size = expected_size;

	return NextExpectedRawBlock(ptr);
}

bool PEBufferMapped::NextExpectedRawBlock(io_ptr_interface& ptr)
{
	vector<PEBlockEntry>& blocks = _expected_blocks;
	uint32_t size;
	dword voffset;

	if (!_parsed) {
		return false;
	}

	bool found = false;
	for (uint32_t i = _expected_inx, count = blocks.size(); i < count; i++) {
		uint32_t diff = _expected_raw - blocks[i].raw;
		blocks[i].raw_size -= diff;
		blocks[i].rva += diff;

		_expected_inx++;

		voffset = blocks[i].rva;
		size = blocks[i].raw_size >= _expected_size ? _expected_size : blocks[i].raw_size;
		if (voffset + size > _buf_size) {
			continue;
		}

		found = true;
		break;
	}
	if (!found) {
		return false;
	}

	ptr = PEBuffer(_buf + voffset, voffset, size);
	return true;
}

bool PEBufferMapped::GetExpectedRvaBlock(io_ptr_interface& ptr, dword rva, uint32_t expected_size)
{
	uint32_t size, inx;

	if (_buf == 0) {
		return false;
	}

	if (rva >= _buf_size) {
		return false;
	}

	if (!_parsed) {// if called before parsing
		uint32_t peak = _buf_size - rva;
		ptr = PEBuffer(_buf + rva, rva, peak < expected_size ? peak : expected_size);
		return true;
	}

	if (!_map.GetBlockInxByRva(rva, inx)) {
		return false;
	}

	size = _map[inx].rva_size - (rva - _map[inx].rva);
	if (size > expected_size) {
		size = expected_size;
	}

	ptr = PEBuffer(_buf + rva, rva, size);
	return true;
}

// ======================= PEBufferRaw =======================

PEBufferRaw::PEBufferRaw() :
	_buf(0),
	_buf_size(0)
{
}

PEBufferRaw::PEBufferRaw(void* buf, uint32_t size)
{
	if (buf == 0) {
		throw exception("parser: invalid buffer ptr");
	}

	_buf = reinterpret_cast<uint8_t*>(buf);
	_buf_size = size;

	Parse();
}

PEBufferRaw::~PEBufferRaw()
{
}

bool PEBufferRaw::Parse(void* buf, uint32_t size)
{
	Clear();

	if (buf == 0 && _buf == 0) {
		return SetError(E_UNKNOWN, __LINE__, "parser: invalid params");
	}
	if (buf != 0) {
		_buf = reinterpret_cast<uint8_t*>(buf);
		_buf_size = size;
	}

	if (_buf_size == 0 && !PEHeaderParser::CalcHeaderSize(_buf, MONSTRA_PE_HEADER_VIRTUAL_MAX_SIZE, &_buf_size)) {
		return SetError(E_UNKNOWN, __LINE__, "parser: can't calculate header size");
	}

	if (!_header.Parse(this)) {
		return InheritErrorFrom(_header);
	}

	if (!_map.Load(_header)) {
		Clear();
		return SetError(E_UNKNOWN, __LINE__, "parser: can't load pe map");
	}

	_parsed = true;
	return SetErrorOK;
}

void PEBufferRaw::Clear()
{
	_header.Clear();
	_map.Clear();
	_parsed = false;
}

bool PEBufferRaw::IsParsed() const
{
	return _parsed;
}

const PEHeaderParser& PEBufferRaw::GetHeader() const
{
	return _header;
}

bool PEBufferRaw::GetMap(PEMap &pemap) const
{
	if (!_parsed) {
		return false;
	}
	pemap = _map;
	return true;
}

bool PEBufferRaw::SetMap(PEMap &pemap)
{
	if (!_parsed) {
		return false;
	}
	_map = pemap;
	return true;
}

bool PEBufferRaw::ConvRawToPtr(io_ptr_interface& ptr, dword raw, uint32_t size)
{
	if (_buf == 0) {
		return false;
	}

	if (!_parsed) {// if called before parsing
		if (raw + size > _buf_size) {
			return false;
		}
		ptr = PEBuffer(_buf + raw, raw, size);
		return true;
	}

	vector<PEBlockEntry> blocks;
	if (!_map.GetRelativeBlockByRaw(raw, blocks)) {
		return false;
	}

	bool found = false;
	for (uint32_t i = 0, count = blocks.size(); i < count; i++) {
		if (blocks[i].raw_size < size) {
			continue;
		}
		if (blocks[i].raw + size <= _buf_size) {
			found = true;
			break;
		}
	}
	if (!found) {
		return false;
	}

	ptr = PEBuffer(_buf + raw, raw, size);
	return true;
}

bool PEBufferRaw::NextRawToPtr(io_ptr_interface& ptr)
{
	return false;
}

bool PEBufferRaw::ConvRvaToPtr(io_ptr_interface& ptr, dword rva, uint32_t size)
{
	PEBlockEntry entry;

	if (_buf == 0) {
		return false;
	}

	if (!_parsed) {// if called before parsing
		if (rva + size > _buf_size) {
			return false;
		}
		ptr = PEBuffer(_buf + rva, rva, size);
		return true;
	}

	if (!_map.GetRelativeBlockByRva(rva, entry)) {
		return false;
	}

	if (entry.raw_size == 0) {
		return false;
	}
	if (entry.raw_size < size) {
		return false;
	}
	if (entry.raw + size > _buf_size) {
		return false;
	}

	ptr = PEBuffer(_buf + entry.raw, entry.raw, size);
	return true;
}

bool PEBufferRaw::GetExpectedRawBlock(io_ptr_interface& ptr, dword raw, uint32_t expected_size)
{
	if (_buf == 0) {
		return false;
	}

	if (raw >= _buf_size) {
		return false;
	}

	if (!_parsed) {// if called before parsing
		uint32_t peak = _buf_size - raw;
		ptr = PEBuffer(_buf + raw, raw, peak < expected_size ? peak : expected_size);
		return true;
	}

	vector<uint32_t> inxs;
	if (!_map.GetBlockInxByRaw(raw, inxs)) {
		return false;
	}

	if (raw + expected_size > _buf_size) {
		expected_size = _buf_size - raw;
	}

	uint32_t size = 0;
	for (uint32_t i = 0, count = inxs.size(); i < count; i++) {
		uint32_t inx = inxs[i];
		uint32_t temp_size = _map[inx].raw_size - (raw - _map[inx].raw);

		if (temp_size > expected_size) {
			size = expected_size;
			break;
		}

		if (temp_size > size) {
			size = temp_size;
		}
	}

	ptr = PEBuffer(_buf + raw, raw, size);
	return true;
}

bool PEBufferRaw::NextExpectedRawBlock(io_ptr_interface& ptr)
{
	return false;
}

bool PEBufferRaw::GetExpectedRvaBlock(io_ptr_interface& ptr, dword rva, uint32_t expected_size)
{
	uint32_t size, inx;

	if (_buf == 0) {
		return false;
	}

	if (!_parsed) {// if called before parsing
		if (rva >= _buf_size) {
			return false;
		}
		uint32_t peak = _buf_size - rva;
		ptr = PEBuffer(_buf + rva, rva, peak < expected_size ? peak : expected_size);
		return true;
	}

	if (!_map.GetBlockInxByRva(rva, inx)) {
		return false;
	}

	if (_map[inx].raw_size == 0) {
		return false;
	}

	uint32_t diff = rva - _map[inx].rva;
	dword roffset = _map[inx].raw + diff;

	if (diff > _map[inx].raw_size) {
		return false;
	}

	size = _map[inx].raw_size - diff;
	if (size > expected_size) {
		size = expected_size;
	}

	if (roffset + expected_size > _buf_size) {
		return false;
	}
	
	ptr = PEBuffer(_buf + roffset, roffset, size);
	return true;
}

// ======================= PERangeMapped =======================

bool PERangeMapped::AddRange(void* buf, dword rva, uint32_t size)
{
	if (size == 0) {
		return false;
	}

	MappedRange entry;
	entry.buf = reinterpret_cast<uint8_t*>(buf);
	entry.rva = rva;
	entry.size = size;
	_ranges.push_back(entry);
	return true;
}

/*
class remove_range_entry {
public:
	void* buf;
	bool removed;
	remove_range_entry(void* b) : buf(b) { }
	bool operator() (const PERangeMapped::MappedRange& entry) 
	{
		if (entry.buf == buf) {
			return removed = true;
		}
		return false; 
	}
};*/

bool PERangeMapped::RemoveRange(void* buf)
{
	list<MappedRange>::iterator it = _ranges.begin();
	for (int i = 0, count = _ranges.size(); i < count; i++, it++) {
		if (it->buf == buf) {
			_ranges.erase(it);
			return true;
		}
	}
	return false;
}

void PERangeMapped::Clear()
{
	_ranges.clear();
}

bool PERangeMapped::ConvRawToPtr(io_ptr_interface& ptr, dword raw, uint32_t size)
{// STUB: can't convert to raw
	return false;
}

bool PERangeMapped::NextRawToPtr(io_ptr_interface& ptr)
{// STUB: can't convert to raw
	return false;
}

bool PERangeMapped::ConvRvaToPtr(io_ptr_interface& ptr, dword rva, uint32_t size)
{
	list<MappedRange>::iterator it = _ranges.begin();
	uint32_t peak = rva + size;
	bool found = false;

	for (int i = 0, count = _ranges.size(); i < count; i++, it++) {
		if (it->rva <= rva && it->rva + it->size >= peak) {
			uint32_t diff = rva - it->rva;
			ptr = PEBuffer(it->buf + diff, rva, it->size - diff);
			found = true;
			break;
		}
	}

	return found;
}

bool PERangeMapped::GetExpectedRawBlock(io_ptr_interface& ptr, dword raw, uint32_t expected_size)
{// STUB: can't convert to raw
	return false;
}

bool PERangeMapped::NextExpectedRawBlock(io_ptr_interface& ptr)
{// STUB: can't convert to raw
	return false;
}

bool PERangeMapped::GetExpectedRvaBlock(io_ptr_interface& ptr, dword rva, uint32_t expected_size)
{
	list<MappedRange>::iterator it = _ranges.begin();
	uint32_t size, peak = rva + expected_size;
	bool found = false;

	for (int i = 0, count = _ranges.size(); i < count; i++, it++) {
		if (it->rva <= rva && it->rva + it->size >= rva) {
			uint32_t diff = rva - it->rva;
			size = it->size - diff;
			if (size > expected_size) {
				size = expected_size;
			}

			ptr = PEBuffer(it->buf + diff, rva, size);
			found = true;
			break;
		}
	}

	return found;
}

};//Monstra
