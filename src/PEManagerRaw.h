#ifndef __PEMANAGERRAW_H
#define __PEMANAGERRAW_H

#include "PEDefs.h"
#include "PEInfo.h"
#include "PEManager.h"
#include "PEDirRelocs.h"


class PEOpenRawParams {
public:
	void *buf;
	unsigned int size;

	PEOpenRawParams() : size(0), buf(NULL) {}
	PEOpenRawParams(void *arg_buf, unsigned int arg_size) : buf(arg_buf), size(arg_size) {}
};

typedef PEOpenRawParams* PPEOpenRawParams;


class CPEManagerRaw : public IPEManager {
	enum { HeaderSize = PE_HEADER_SIZE };

	void *_header_buf;
	void *_raw_buf;

public:
	CPEManagerRaw();
	~CPEManagerRaw();

	bool Open(PEOpenRawParams &params, bool use_relocs, bool readonly = false);

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