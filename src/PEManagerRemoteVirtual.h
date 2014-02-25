#ifndef __PEMANAGERREMOTEVIRTUAL_H
#define __PEMANAGERREMOTEVIRTUAL_H

#include "PEDefs.h"
#include "PEInfo.h"
#include "PEManager.h"
#include "PEDirRelocs.h"
#include"PEManagerVirtual.h"


class PEOpenRemoteParams {
public:
	DWORD pid;
	HMODULE hmod;

	PEOpenRemoteParams() : pid(0), hmod(NULL) {}
	PEOpenRemoteParams(DWORD arg_pid, HMODULE arg_hmod) : pid(arg_pid), hmod(arg_hmod) {}
};

typedef PEOpenRemoteParams* PPEOpenRemoteParams;


class CPEManagerRemoteVirtual : public IPEManager {
private:
	enum { HeaderSize = PE_HEADER_SIZE };

	HANDLE _hproc;
	HMODULE _hmod;
	void *_header_buf;
	unsigned int _virt_size;

	DWORD _old_protect;
	void *_old_addr;
	unsigned int _old_size;

	bool SetWrAccess(void *addr, int size);
	inline bool RestoreAccess();
	bool CompareModuleNames(char *path1, char *path2);

public:
	CPEManagerRemoteVirtual();
	~CPEManagerRemoteVirtual();

	bool Open(PEOpenRemoteParams &params, bool use_relocs, bool readonly = false);

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