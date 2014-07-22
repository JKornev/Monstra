#ifndef __MONSTRA_PE_HEADER_H
#define __MONSTRA_PE_HEADER_H

#include "PEDefs.h"
#include "PEParser.h"
#include "IOPointer.h"
#include "ErrorHandler.h"
#include <vector>

namespace Monstra {

class PEMap;
class PESourceInterface;

// Parser

class PEHeaderParser : public MONSTRA_ERROR_CTRL {
public:
	PEHeaderParser();
	~PEHeaderParser();

	bool Parse(PESourceInterface* src);
	void Clear();

	bool IsParsed() const;

	//Parser
	bool ParseMap(PEMap& pemap);

	// Information
	PEArchitecture       GetArch() const;
	PEImgDosHeader_ptr&   GetDos();
	PEImgFileHeader_ptr&  GetImg();
	PEImgOptHeader32_ptr& GetOpt32();
	PEImgOptHeader64_ptr& GetOpt64();
	PEImgDataDir_ptr&     GetDataDir();
	PEImgNtHeaders32_ptr& GetHeader32();
	PEImgNtHeaders64_ptr& GetHeader64();

	PEImgSectionHeader_ptr& GetSectors();
	//PEImgSectionHeader_ptr& GetSectorByPos(uint16_t pos);

	bool HaveDataDir(uint32_t num);

	// Sections
	int FindFirstSectorPosByName(char* name);
	int FindFirstSectorPosByRaw(dword roffset);

	int FindSectorPosByVirtual(dword voffset);
	bool FindSectorPosByName(char* name, std::vector<int>& positions);
	bool FindSectorPosByRaw(dword roffset, std::vector<int>& positions);

	// Alignment
	uint32_t GetVirtualAlignment() const;
	uint32_t GetRawAlignment() const;

	// Size
	uint32_t GetHeaderSize() const;

public:
	static bool CalcHeaderSize(void* buf, uint32_t size, uint32_t* pheader_size);

private:
	bool _is_parsed;

	PEArchitecture         _arch;

	// PE structures
	PEImgDosHeader_ptr     _pdos;
	PEImgFileHeader_ptr    _pimg;
	PEImgOptHeader32_ptr   _popt32;
	PEImgOptHeader64_ptr   _popt64;
	PEImgDataDir_ptr       _pdir;
	PEImgNtHeaders32_ptr   _pheader32;
	PEImgNtHeaders64_ptr   _pheader64;

	PEImgSectionHeader_ptr _psects;
	uint16_t               _sect_count;

	uint32_t               _header_size;

	uint32_t               _virt_align;
	uint32_t               _raw_align;

};

class PEHeader {

};

};//Monstra

#endif
