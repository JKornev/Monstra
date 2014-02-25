#include "PEManagerVirtual.h"


CPEManagerVirtual::CPEManagerVirtual() : _header_buf(NULL)
{
	_runtime_object = true;
}

CPEManagerVirtual::~CPEManagerVirtual()
{
	CloseObject();
}

bool CPEManagerVirtual::Open(HMODULE module, bool use_relocs, bool readonly)
{
	return IPEManager::Open(module, use_relocs, readonly);
}

bool CPEManagerVirtual::OpenObject(void *handle)
{
	MEMORY_BASIC_INFORMATION mbi;

	_module = handle;
	
	if (!VirtualQuery(handle, &mbi, PE_HEADER_SIZE)) {
		return SetError(E_SYSTEM, GetLastError(), "can't query memory");
	}
	if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_EXECUTE || *(PWORD)handle != IMAGE_DOS_SIGNATURE) {
		return SetError(E_UNKNOWN, __LINE__, NULL);
	}

	_header_buf = VirtualAlloc(NULL, PE_HEADER_SIZE, MEM_COMMIT, PAGE_READWRITE);
	if (!_header_buf) {
		return SetError(E_SYSTEM, GetLastError(), "can't allocate memory");
	}

	//setup here because it's const info
#if (PE_SYSTEM_WIN64 == 1)
	_imgbase.val64 = (ULONGLONG)handle;
#else
	_imgbase.val32l = (DWORD)handle;
	_imgbase.val32h = 0;
#endif

	return SetErrorOK;
}

void CPEManagerVirtual::CloseObject()
{
	if (_header_buf) {
		VirtualFree(_header_buf, 0, MEM_RELEASE);
		_header_buf = NULL;
	}
}

bool CPEManagerVirtual::ReloadObjectHeader()
{
	unsigned int sect_count = 0, temp;
	PIMAGE_SECTION_HEADER psect;

	if (!SetWrAccess(_module, HeaderSize)) {
		return SetError(E_ACCESS_DENIED, __LINE__, NULL);
	}
	memcpy(_header_buf, _module, HeaderSize);
	if (!RestoreAccess()) {
		return SetError(E_UNKNOWN, __LINE__, NULL);
	}

	if (!ParseHeader(_header_buf)) {
		return SetErrorInherit;
	}

	if (GetArch() == PE_32) {
		_virt_size = Alignment32(GetHOpt32()->SizeOfImage, PE_DEFAULT_VIRTUAL_ALIGNMENT);
	} else {
		_virt_size = Alignment32(GetHOpt64()->SizeOfImage, PE_DEFAULT_VIRTUAL_ALIGNMENT);
	}

	psect = GetSectorPtr(&sect_count);
	_module_size = 0;
	for (unsigned int i = 0; i < sect_count; i++) {
		temp = psect[i].PointerToRawData + Alignment32(psect[i].SizeOfRawData, PE_DEFAULT_FILE_ALIGNMENT);
		if (temp > _module_size) {
			_module_size = temp;
		}
	}

	return SetErrorOK;
}

bool CPEManagerVirtual::ReadObjectHeaderData(void *pbuffer, unsigned int buf_size, unsigned int *readed)
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

bool CPEManagerVirtual::WriteObjectHeader(void *pbuffer, unsigned int  size)
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

bool CPEManagerVirtual::ReadObjectRawData(DWORD roffset, void *pbuffer, unsigned int  size)
{
	DWORD voffset;
	unsigned int vsize;

	if (ConvRawToVirtual(roffset, &voffset, &vsize) == PE_MAP_OUT_OF_RANGE || vsize < size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	if (!ReadObjectVirtualData(voffset, pbuffer, size)) {
		return SetErrorInherit;
	}
	return SetErrorOK;
}

bool CPEManagerVirtual::WriteObjectRawData(DWORD roffset, void *pbuffer, unsigned int  size)
{
	DWORD voffset;
	unsigned int vsize;

	if (ConvRawToVirtual(roffset, &voffset, &vsize) == PE_MAP_OUT_OF_RANGE || vsize < size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	if (!WriteObjectVirtualData(voffset, pbuffer, size)) {
		return SetErrorInherit;
	}
	return SetErrorOK;
}

bool CPEManagerVirtual::ReadObjectVirtualData(DWORD voffset, void *pbuffer, unsigned int  size)
{
	void *addr = (void *)((uintptr_t)_module + voffset);
	if (voffset + size > _virt_size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	if (!SetWrAccess(addr, size)) {
		return SetError(E_ACCESS_DENIED, __LINE__, NULL);
	}
	memcpy(pbuffer, addr, size);
	if (!RestoreAccess()) {
		return SetError(E_UNKNOWN, __LINE__, NULL);
	}
	return SetErrorOK;
}

bool CPEManagerVirtual::WriteObjectVirtualData(DWORD voffset, void *pbuffer, unsigned int  size)
{
	void *addr = (void *)((uintptr_t)_module + voffset);
	if (voffset + size > _virt_size) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	if (!SetWrAccess(addr, size)) {
		return SetError(E_ACCESS_DENIED, __LINE__, NULL);
	}
	memcpy(pbuffer, addr, size);
	if (!RestoreAccess()) {
		return SetError(E_UNKNOWN, __LINE__, NULL);
	}
	return SetErrorOK;
}

bool CPEManagerVirtual::ReloadObjectRelocs()
{
	_rels.RemoveAll();
	return _rels.LoadDir(this);
}

bool CPEManagerVirtual::SetWrAccess(void *addr, int size)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (!VirtualQuery(addr, &mbi, PE_HEADER_SIZE)) {
		return false;
	}
	if (mbi.Protect != PAGE_EXECUTE && mbi.Protect != PAGE_EXECUTE_READ 
	&& mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_READONLY) {
		_old_addr = NULL;
		return true;
	}

	_old_addr = addr;
	_old_size = size;

	if (!VirtualProtect(_old_addr, _old_size, PAGE_EXECUTE_READWRITE, &_old_protect)) {
		return false;
	}

	return true;
}

bool CPEManagerVirtual::RestoreAccess()
{
	if (!_old_addr) {
		return true;
	}
	if (!VirtualProtect(_old_addr, _old_size, _old_protect, &_old_protect)) {
		return false;
	}
	return true;
}
