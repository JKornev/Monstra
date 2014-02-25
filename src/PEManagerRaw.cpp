#include "PEManagerRaw.h"


CPEManagerRaw::CPEManagerRaw()
{
}

CPEManagerRaw::~CPEManagerRaw()
{
	CloseObject();
}

bool CPEManagerRaw::Open(PEOpenRawParams &params, bool use_relocs, bool readonly)
{
	return IPEManager::Open(&params, use_relocs, readonly);
}

bool CPEManagerRaw::OpenObject(void *handle)
{
	PPEOpenRawParams params = (PPEOpenRawParams)handle;

	_raw_buf = params->buf;
	_module_size = params->size;
	if (_module_size < HeaderSize) {
		return SetError(E_OUT_OF_RANGE, __LINE__, "module too small");
	}

	_header_buf = VirtualAlloc(NULL, HeaderSize, MEM_COMMIT, PAGE_READWRITE);
	if (!_header_buf) {
		return SetError(E_SYSTEM, GetLastError(), "can't allocate memory");
	}

	return SetErrorOK;
}

void CPEManagerRaw::CloseObject()
{
	if (_header_buf) {
		VirtualFree(_header_buf, 0, MEM_RELEASE);
		_header_buf = NULL;
	}
}

bool CPEManagerRaw::ReloadObjectHeader()
{
	memcpy(_header_buf, _raw_buf, HeaderSize);

	if (!ParseHeader(_header_buf)) {
		return SetErrorInherit;
	}

	if (GetArch() == PE_32) {
		_imgbase.val32l = GetHOpt32()->ImageBase;
		_imgbase.val32h = 0;
	} else {
		_imgbase.val64 = GetHOpt64()->ImageBase;
	}

	return SetErrorOK;
}

bool CPEManagerRaw::ReadObjectHeaderData(void *pbuffer, unsigned int buf_size, unsigned int *readed)
{
	unsigned int header_size;

	if (GetArch() == PE_32) {
		header_size = GetHOpt32()->SizeOfHeaders;
	} else {
		header_size = GetHOpt64()->SizeOfHeaders;
	}

	if (header_size > HeaderSize || header_size > buf_size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}

	if (!ReadObjectRawData(0, pbuffer, header_size)) {
		return SetErrorInherit;
	}

	*readed = header_size;
	return SetErrorOK;
}

bool CPEManagerRaw::WriteObjectHeader(void *pbuffer, unsigned int  size)
{
	unsigned int header_size;

	if (GetArch() == PE_32) {
		header_size = GetHOpt32()->SizeOfHeaders;
	} else {
		header_size = GetHOpt64()->SizeOfHeaders;
	}

	if (!pbuffer) {
		pbuffer = _header_buf;
		size = header_size;
	} else if (size > header_size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}

	if (!WriteObjectRawData(0, pbuffer, size)) {
		return SetErrorInherit;
	}
	if (!ReloadHeader()) {
		return SetErrorInherit;
	}

	return SetErrorOK;
}

bool CPEManagerRaw::ReadObjectRawData(DWORD roffset, void *pbuffer, unsigned int  size)
{
	if (roffset + size > _module_size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	memcpy(pbuffer, (void *)((uintptr_t)_raw_buf + roffset), size);
	return SetErrorOK;
}

bool CPEManagerRaw::WriteObjectRawData(DWORD roffset, void *pbuffer, unsigned int  size)
{
	if (roffset + size > _module_size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	memcpy((void *)((uintptr_t)_raw_buf + roffset), pbuffer, size);
	return SetErrorOK;
}

bool CPEManagerRaw::ReadObjectVirtualData(DWORD voffset, void *pbuffer, unsigned int  size)
{
	DWORD roffset;
	unsigned int rsize;

	if (ConvVirtualToRaw(voffset, &roffset, &rsize) == PE_MAP_OUT_OF_RANGE || rsize < size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	if (!ReadObjectRawData(roffset, pbuffer, size)) {
		return SetErrorInherit;
	}
	return SetErrorOK;
}

bool CPEManagerRaw::WriteObjectVirtualData(DWORD voffset, void *pbuffer, unsigned int  size)
{
	DWORD roffset;
	unsigned int rsize;

	if (ConvVirtualToRaw(voffset, &roffset, &rsize) == PE_MAP_OUT_OF_RANGE || rsize < size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	if (!WriteObjectRawData(roffset, pbuffer, size)) {
		return SetErrorInherit;
	}
	return SetErrorOK;
}

bool CPEManagerRaw::ReloadObjectRelocs()
{
	_rels.RemoveAll();
	return _rels.LoadDir(this);
}