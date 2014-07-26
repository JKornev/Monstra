#ifndef __MONSTRA_PE_INFO_DIR_H
#define __MONSTRA_PE_INFO_DIR_H

#include "PEDefs.h"
#include "PEParser.h"
#include "PEHeader.h"
#include "PEMap.h"
#include "ErrorHandler.h"

namespace Monstra {

class PESectionsParser;
class PESections;
class PEExportsParser;
class PEExports;
class PEImportsParser;
class PEImports;
class PERelocsParser;
class PERelocs;
class PEResourcesParser;
class PEResources;

class PEParser : public PESourceInterface, public MONSTRA_ERROR_CTRL {
public:
	PEParser();

	bool ParseHeader(PEHeaderParser &parser);
	bool ParseHeader(PEHeader &header);

	//bool ParseSections(PESectionsParser &parser);
	bool ParseSections(PESections &sections);

	bool ParseExports(PEExportsParser &parser);
	bool ParseExports(PEExports &exports);

	bool ParseImports(PEImportsParser &parser);
	bool ParseImports(PEImports &imports);

	bool ParseRelocs(PERelocsParser &parser);
	bool ParseRelocs(PERelocs &relocs);

	bool ParseResources(PEResourcesParser &parser);
	bool ParseResources(PEResources &resources);

protected:
	bool _parsed;
	PEHeaderParser _header;
};

class PEBufferMapped : public PEParser
{
public:
	PEBufferMapped();
	PEBufferMapped(void* buf, uint32_t size = 0);
	~PEBufferMapped();

	bool Parse(void* buf = 0, uint32_t size = 0);
	void Clear();

	bool IsParsed() const;

	PEHeaderParser& GetHeader();
	bool GetMap(PEMap &pemap) const;
	bool SetMap(PEMap &pemap);

public:
	virtual bool ConvRawToPtr(io_ptr_interface& ptr, dword raw, uint32_t size);
	virtual bool NextRawToPtr(io_ptr_interface& ptr);
	virtual bool ConvRvaToPtr(io_ptr_interface& ptr, dword rva, uint32_t size);
	virtual bool GetExpectedRawBlock(io_ptr_interface& ptr, dword raw, uint32_t expected_size);
	virtual bool NextExpectedRawBlock(io_ptr_interface& ptr);
	virtual bool GetExpectedRvaBlock(io_ptr_interface& ptr, dword rva, uint32_t expected_size);

protected:
	//PEHeaderParser _header;
	PEMap _map;

	uint8_t* _buf;
	uint32_t _buf_size;

	// ConvRawToPtr context
	std::vector<PEBlockEntry> _conv_blocks;
	uint32_t _conv_inx;
	uint32_t _conv_size;

	// GetExpectedRawBlock context
	std::vector<PEBlockEntry> _expected_blocks;
	uint32_t _expected_inx;
	uint32_t _expected_raw;
	uint32_t _expected_size;
};

class PEBufferRaw : public PEParser
{
public:
	PEBufferRaw();
	PEBufferRaw(void* buf, uint32_t size = 0);
	~PEBufferRaw();

	bool Parse(void* buf = 0, uint32_t size = 0);
	void Clear();

	bool IsParsed() const;

	const PEHeaderParser& GetHeader() const;
	bool GetMap(PEMap &pemap) const;
	bool SetMap(PEMap &pemap);

public:
	virtual bool ConvRawToPtr(io_ptr_interface& ptr, dword raw, uint32_t size);
	virtual bool NextRawToPtr(io_ptr_interface& ptr);
	virtual bool ConvRvaToPtr(io_ptr_interface& ptr, dword rva, uint32_t size);
	virtual bool GetExpectedRawBlock(io_ptr_interface& ptr, dword raw, uint32_t expected_size);
	virtual bool NextExpectedRawBlock(io_ptr_interface& ptr);
	virtual bool GetExpectedRvaBlock(io_ptr_interface& ptr, dword rva, uint32_t expected_size);

protected:
	//PEHeaderParser _header;
	PEMap _map;

	uint8_t* _buf;
	uint32_t _buf_size;
};

struct _PEMappedRange;

class PERangeMapped : public PESourceInterface, public MONSTRA_ERROR_CTRL {
public:
	bool AddRange(void* buf, dword rva, uint32_t size);
	bool RemoveRange(void* buf);
	void Clear();

public:
	virtual bool ConvRawToPtr(io_ptr_interface& ptr, dword raw, uint32_t size);
	virtual bool NextRawToPtr(io_ptr_interface& ptr);
	virtual bool ConvRvaToPtr(io_ptr_interface& ptr, dword rva, uint32_t size);
	virtual bool GetExpectedRawBlock(io_ptr_interface& ptr, dword raw, uint32_t expected_size);
	virtual bool NextExpectedRawBlock(io_ptr_interface& ptr);
	virtual bool GetExpectedRvaBlock(io_ptr_interface& ptr, dword rva, uint32_t expected_size);

public:
	struct MappedRange {
		uint8_t* buf;
		uint32_t rva;
		uint32_t size;
	};

private:
	std::list<MappedRange> _ranges;
};

};//Monstra

#endif
