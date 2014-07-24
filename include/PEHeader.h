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
	bool ParseMap(PEMap& pemap) const;

	// Information
	PEArchitecture        GetArch() const;

	PEImgDosHeader_ptr&   GetDos();
	PEImgFileHeader_ptr&  GetImg();
	PEImgOptHeader32_ptr& GetOpt32();
	PEImgOptHeader64_ptr& GetOpt64();
	PEImgDataDir_ptr&     GetDataDir();
	PEImgNtHeaders32_ptr& GetHeader32();
	PEImgNtHeaders64_ptr& GetHeader64();
	PEImgSectionHeader_ptr& GetSectors();

	const PEImgDosHeader_ptr&   GetDos() const;
	const PEImgFileHeader_ptr&  GetImg() const;
	const PEImgOptHeader32_ptr& GetOpt32() const;
	const PEImgOptHeader64_ptr& GetOpt64() const;
	const PEImgDataDir_ptr&     GetDataDir() const;
	const PEImgNtHeaders32_ptr& GetHeader32() const;
	const PEImgNtHeaders64_ptr& GetHeader64() const;
	const PEImgSectionHeader_ptr& GetSectors() const;

	bool HaveDataDir(uint32_t num) const;

	// Sections
	int FindFirstSectorPosByName(char* name) const;
	int FindFirstSectorPosByRaw(dword roffset) const;

	int FindSectorPosByVirtual(dword voffset) const;
	bool FindSectorPosByName(char* name, std::vector<int>& positions) const;
	bool FindSectorPosByRaw(dword roffset, std::vector<int>& positions) const;

	// Alignment
	uint32_t GetVirtualAlignment() const;
	uint32_t GetRawAlignment() const;

	// Size
	uint32_t GetHeaderSize() const;

	// Misc
	uint32_t GetChecksum() const;

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
public:
	PEHeader();
	~PEHeader();

	bool Create(PEArchitecture arch);
	bool Load(PEHeaderParser &parser);

	PEArchitecture GetArch() const;

	void GetDos(PEImgDosHeader& dos) const;
	void SetDos(PEImgDosHeader& dos);

	void GetImg(PEImgFileHeader& img) const;
	void SetImg(PEImgFileHeader& img);

	bool GetOpt32(PEImgOptHeader32& opt) const;
	bool SetOpt32(PEImgOptHeader32& opt);

	bool GetOpt64(PEImgOptHeader64& opt) const;
	bool SetOpt64(PEImgOptHeader64& opt);

	bool GetHeader32(PEImgNtHeaders32& header) const;
	bool SetHeader32(PEImgNtHeaders32& header);

	bool GetHeader64(PEImgNtHeaders64& header) const;
	bool SetHeader64(PEImgNtHeaders64& header);

	bool GetDir(uint8_t num, PEImgDataDir& dir) const;
	bool SetDir(uint8_t num, PEImgDataDir& dir);

	// File header
	uint16_t GetImgMachine() const;
	void SetImgMachine(uint16_t machine);

	uint32_t GetImgTimestamp() const;
	void SetImgTimestamp(uint32_t stamp);

	uint16_t GetImgCharacteristics() const;
	void SetImgCharacteristics(uint16_t chcs);

	// Optional header
	uint32_t GetOptVirtualAlignment() const;
	void SetOptVirtualAlignment(uint32_t valign);

	uint32_t GetOptRawAlignment() const;
	void SetOptRawAlignment(uint32_t ralign);

	uint16_t GetOptSubsystem() const;
	void SetOptSubsystem(uint16_t subsys);

	uint32_t GetOptEntryPoint() const;
	void SetOptEntryPoint(uint32_t ep);

	UAddress GetOptImageBase() const;
	void SetOptImageBase(UAddress addr);

private:
	PEArchitecture _arch;
	PEImgDosHeader _dos;
	PEImgNtHeaders32 _header32;
	PEImgNtHeaders64 _header64;
	pPEImgFileHeader _pimg;
	pPEImgOptHeader32 _popt32;
	pPEImgOptHeader64 _popt64;
	pPEImgDataDir _pdir;
};

// Builder

class PEHeaderBuilder {
public:
	PEHeaderBuilder();
	~PEHeaderBuilder();

};

};//Monstra

#endif
