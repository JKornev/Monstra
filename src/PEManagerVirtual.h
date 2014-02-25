#ifndef __PEMANAGERVIRTUAL_H
#define __PEMANAGERVIRTUAL_H

#include "PEDefs.h"
#include "PEInfo.h"
#include "PEManager.h"
#include "PEDirRelocs.h"


class CPEManagerVirtual : public IPEManager {
protected:
	enum { HeaderSize = PE_HEADER_SIZE };

	void *_module;
	void *_header_buf;
	unsigned int _virt_size;

	DWORD _old_protect;
	void *_old_addr;
	unsigned int _old_size;

	bool SetWrAccess(void *addr, int size);
	inline bool RestoreAccess();

public:
	CPEManagerVirtual();
	~CPEManagerVirtual();

	bool Open(HMODULE module, bool use_relocs, bool readonly = false);

private:
	bool OpenObject(void *handle);
	void CloseObject();

	bool ReloadObjectHeader();
	bool ReadObjectHeaderData(void *pbuffer, unsigned int buf_size, unsigned int *readed);
	bool WriteObjectHeader(void *pbuffer = NULL, unsigned int  size = PE_HEADER_RAW_SIZE);

	bool ReadObjectRawData(DWORD roffset, void *pbuffer, unsigned int  size);
	bool WriteObjectRawData(DWORD roffset, void *pbuffer, unsigned int  size);

	bool ReadObjectVirtualData(DWORD voffset, void *pbuffer, unsigned int  size);
	bool WriteObjectVirtualData(DWORD voffset, void *pbuffer, unsigned int  size);

	bool ReloadObjectRelocs();
};

#endif