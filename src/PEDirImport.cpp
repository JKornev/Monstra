#include "PEDirImport.h"
#include "PEManager.h"
#include "PEBuffer.h"


CPEDirImport::CPEDirImport(bool merge_mode) : _guid(0)
{
	_merge_if_exist = merge_mode;
	ClearEnums();
}

CPEDirImport::~CPEDirImport()
{
	RemoveAllLibs();
}

bool CPEDirImport::LoadDir(IPEManager *pmngr, DWORD dir_offset, bool error_on_iat_merge)
{
	enum { LibNameLen = 25 };
	enum { ProcLookupLen = 20 };
	PIMAGE_DATA_DIRECTORY pdir_descr;
	IMAGE_IMPORT_DESCRIPTOR imp;
	DWORD sort_inx = 0;
	CPEBuffer buf(pmngr);
	unsigned int word_size;

	if (!pmngr->IsOpened()) {
		return false;
	}

	if (!dir_offset) {
		pdir_descr = &pmngr->GetHDataDir()[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!pdir_descr->VirtualAddress || !pdir_descr->Size) {
			return true;//not found OK
		}

		dir_offset = pdir_descr->VirtualAddress;
	}
	
	word_size = (pmngr->GetArch() == PE_32 ? sizeof(DWORD) : sizeof(ULONGLONG));
	do {
		unsigned int block_size, id, buf_len, len, count;
		DWORD roffset;
		char *pname;

		if (!pmngr->ReadVirtualData(dir_offset, &imp, sizeof(imp))) {
			return false;
		}
		if (!imp.Name) {
			break;
		}

		//load library name
		buf_len = LibNameLen;
		if (pmngr->ConvVirtualToRaw(imp.Name, &roffset, &block_size) == PE_MAP_OUT_OF_RANGE || block_size < 4) {
			return false;
		}
		if (buf_len > block_size) {
			buf_len = block_size;
		}

		do {
			pname = (char *)buf.GetRawDataBlock(roffset, buf_len);
			if (!pname) {
				return false;
			}

			if (!IsZeroEndStr(pname, buf_len, len)) {//try read more data
				if (buf_len == block_size) {
					return false;//can't load more data
				}

				buf_len += LibNameLen;
				if (buf_len > block_size) {
					buf_len = block_size;
				}

				buf.FreeDataBlock(pname);
			} else {
				break;
			}
		} while (true);

		AddLib(pname, sort_inx, &id);
		buf.FreeDataBlock(pname);

		//load lookup table
		if (pmngr->IsRuntimeObject() && imp.OriginalFirstThunk == imp.FirstThunk) {
			if (error_on_iat_merge) {
				return false;//iat and lookup is merged
			} else {
				continue;//can't load procedures
			}
		}

		if (imp.OriginalFirstThunk == 0) {
			imp.OriginalFirstThunk = imp.FirstThunk;
		}

		if (!SetLibOffset(id, imp.OriginalFirstThunk, imp.FirstThunk)) {
			return false;
		}

		count = ProcLookupLen;
		buf_len = count * word_size;
		if (pmngr->ConvVirtualToRaw(imp.OriginalFirstThunk, &roffset, &block_size) == PE_MAP_OUT_OF_RANGE || !block_size) {
			return false;
		}
		if (buf_len > block_size) {
			count = block_size / word_size;
			buf_len = count * word_size;
		}

		do {
			int res;

			if (pmngr->GetArch() == PE_32) {
				res = LoadLookupTable<DWORD>(pmngr, roffset, count, buf_len, id, buf);
			} else {
				res = LoadLookupTable<ULONGLONG>(pmngr, roffset, count, buf_len, id, buf);
			}
			
			if (res == 0) {//fail
				return false;
			} else if (res == 1) {//ok
				break;
			} else if (res == -1) {//realloc
				if (buf_len == block_size) {
					return false;
				}

				roffset += buf_len;
				block_size -= buf_len;
				if (buf_len > block_size) {
					count = block_size / word_size;
					buf_len = count * word_size;
				}
				if (!buf_len) {
					return false;
				}
			}
		} while (true);

		dir_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		sort_inx++;
	} while (true);

	return true;
}

template<typename T>
int CPEDirImport::LoadLookupTable(IPEManager *pmngr, DWORD roffset, 
	unsigned int count, unsigned int buf_len, unsigned int lib_id, CPEBuffer &buf)
{
	enum { ProcNameLen = 25 };
	T *pthunk;
	unsigned int id, name_block_size, len;
	PIMAGE_IMPORT_BY_NAME pname;

	pthunk = (T *)buf.GetRawDataBlock(roffset, buf_len);
	if (!pthunk) {
		return 0;
	}

	for (unsigned int i = 0; i < count; i++) {
		if (!pthunk[i]) {
			return 1;//end of table
		}

		if (pthunk[i] & _BIT((sizeof(T) * 8) - 1)) {
			if (!AddProcByOrdinal(lib_id, (WORD)pthunk[i], &id)) {
				return 0;
			}
		} else {
			//load name
			buf_len = ProcNameLen;
			if (pmngr->ConvVirtualToRaw((DWORD)pthunk[i], &roffset, &name_block_size) == PE_MAP_OUT_OF_RANGE 
			|| name_block_size < sizeof(IMAGE_IMPORT_BY_NAME)) {
				return 0;
			}
			if (buf_len > name_block_size) {
				buf_len = name_block_size;
			}

			//load name
			do {
				pname = (PIMAGE_IMPORT_BY_NAME)buf.GetRawDataBlock(roffset, buf_len);
				if (!pname) {
					return 0;
				}

				if (!IsZeroEndStr((char *)pname->Name, buf_len, len)) {//try read more data
					if (buf_len == name_block_size) {
						return 0;//can't load more data
					}

					buf_len += ProcNameLen;
					if (buf_len > name_block_size) {
						buf_len = name_block_size;
					}

					buf.FreeDataBlock(pname);
				} else {
					break;
				}
			} while (buf_len <= name_block_size);

			if (!AddProcByName(lib_id, (char *)pname->Name, pname->Hint, &id, i)) {
				return 0;
			}
			buf.FreeDataBlock(pname);
		}
	}
	
	return -1;//need more data
}

void CPEDirImport::AddLib(char *lib_name, int order, unsigned int *lib_id)
{
	list<Import_Library>::iterator it;
	Import_Library lib;
	unsigned int id;

	if (_merge_if_exist && GetLibId(lib_name, &id)) {
		*lib_id = id;
		return;
	}

	lib.lib_id = GenGuid();
	lib.name = lib_name;
	lib.order = order;
	lib.offset_iat = 0;
	lib.offset_lookup = 0;
	//lib.proc_block_size = 0;
	_libs.push_back(lib);
	*lib_id = lib.lib_id;
}

bool CPEDirImport::RemoveLib(unsigned int lib_id)
{
	list<Import_Library>::iterator it;
	if (!FindLib(lib_id, it)) {
		return false;
	}

	_libs.erase(it);
	ClearEnums();
	return true;
}

void CPEDirImport::RemoveAllLibs()
{
	_libs.clear();
	ClearEnums();
}

bool CPEDirImport::SetLibOffset(unsigned int lib_id, DWORD lookup, DWORD iat)
{
	list<Import_Library>::iterator it_lib;

	if (!FindLib(lib_id, it_lib)) {
		return false;
	}

	it_lib->offset_iat = iat;
	it_lib->offset_lookup = lookup;

	return true;
}

bool CPEDirImport::AddProcByName(unsigned int lib_id, char *proc_name, unsigned short hint, unsigned int *proc_id, int inx)
{
	list<Import_Library>::iterator it_lib;
	list<Import_Procedure>::iterator it_proc;
	Import_Procedure proc;
	unsigned int id;

	if (!FindLib(lib_id, it_lib)) {
		return false;
	}

	if (_merge_if_exist && GetProcId(lib_id, proc_name, &id)) {
		*proc_id = id;
		return true;
	}

	proc.proc_id = GenGuid();
	proc.hint = hint;
	proc.name = proc_name;
	proc.ordinal = 0;
	proc.use_ordinal = false;
	proc.inx = inx;
	it_lib->proc.push_back(proc);
	*proc_id = proc.proc_id;

	return true;
}

bool CPEDirImport::AddProcByOrdinal(unsigned int lib_id, unsigned short ordinal, unsigned int *proc_id, int inx)
{
	list<Import_Library>::iterator it_lib;
	list<Import_Procedure>::iterator it_proc;
	Import_Procedure proc;
	unsigned int id;

	if (!FindLib(lib_id, it_lib)) {
		return false;
	}

	if (_merge_if_exist && GetProcId(lib_id, ordinal, &id)) {
		*proc_id = id;
		return true;
	}

	proc.proc_id = GenGuid();
	proc.hint = 0;
	proc.ordinal = ordinal;
	proc.use_ordinal = true;
	it_lib->proc.push_back(proc);
	*proc_id = proc.proc_id;

	return true;
}

bool CPEDirImport::RemoveProc(unsigned int lib_id, unsigned int proc_id)
{
	list<Import_Library>::iterator it_lib;
	list<Import_Procedure>::iterator it_proc;

	if (!FindLib(lib_id, it_lib)) {
		return false;
	}

	if (!FindProc(proc_id, it_lib, it_proc)) {
		return false;
	}

	it_lib->proc.erase(it_proc);
	_active_enum_proc = false;

	return true;
}

bool CPEDirImport::RemoveAllProc(unsigned int lib_id)
{
	list<Import_Library>::iterator it_lib;

	if (!FindLib(lib_id, it_lib)) {
		return false;
	}

	it_lib->proc.clear();
	_active_enum_proc = false;

	return true;
}

bool CPEDirImport::GetLibId(char *lib_name, unsigned int *lib_id)
{
	list<Import_Library>::iterator it_lib;
	string str;

	if (_merge_if_exist) {
		if (lib_name) {
			it_lib = _libs.begin();
			str = lib_name;
		} else {
			it_lib = _find_lib;
			str = it_lib->name;
			it_lib++;
		}
		
	} else {
		if (!lib_name) {
			return false;
		}
		it_lib = _libs.begin();
		str = lib_name;
	}

	while (it_lib != _libs.end()) {
		if (!_strcmpi(str.c_str(), it_lib->name.c_str())) {
			*lib_id = it_lib->lib_id;
			return true;
		}
		it_lib++;
	}
	return false;
}

bool CPEDirImport::GetProcId(unsigned int lib_id, char *proc_name, unsigned int *proc_id)
{
	list<Import_Library>::iterator it_lib;
	list<Import_Procedure>::iterator it_proc;
	string str;

	if (!FindLib(lib_id, it_lib)) {
		return false;
	}

	if (_merge_if_exist) {
		if (proc_name) {
			it_proc = it_lib->proc.begin();
			str = proc_name;
		} else {
			it_proc = _find_proc;
			str = it_proc->name;
			it_proc++;
		}
	} else {
		if (!proc_name) {
			return false;
		}
		it_proc = it_lib->proc.begin();
		str = proc_name;
	}

	while (it_proc != it_lib->proc.end()) {
		if (!it_proc->use_ordinal &&  !strcmp(proc_name, it_proc->name.c_str())) {
			*proc_id = it_proc->proc_id;
			return true;
		}
		it_proc++;
	}
	return false;
}

bool CPEDirImport::GetProcId(unsigned int lib_id, unsigned short ordinal, unsigned int *proc_id)
{
	list<Import_Library>::iterator it_lib;
	list<Import_Procedure>::iterator it_proc;

	if (!FindLib(lib_id, it_lib)) {
		return false;
	}

	if (_merge_if_exist) {
		if (ordinal != -1) {
			it_proc = it_lib->proc.begin();
		} else {
			it_proc = _find_proc;
			it_proc++;
		}
	} else {
		it_proc = it_lib->proc.begin();
	}

	while (it_proc != it_lib->proc.end()) {
		if (it_proc->use_ordinal &&  it_proc->ordinal == ordinal) {
			*proc_id = it_proc->proc_id;
			return true;
		}
		it_proc++;
	}
	return false;
}

unsigned int CPEDirImport::GetLibCount()
{
	return _libs.size();
}

unsigned int CPEDirImport::GetProcCount(unsigned int lib_id)
{
	list<Import_Library>::iterator it_lib;
	if (!FindLib(lib_id, it_lib)) {
		return 0;
	}
	return it_lib->proc.size();
}

bool CPEDirImport::GetLibInfo(unsigned int lib_id, PPEImportLibElem lib_struct)
{
	list<Import_Library>::iterator it_lib;
	if (!FindLib(lib_id, it_lib)) {
		return false;
	}

	CopyLibElem(lib_struct, &*it_lib);
	return true;
}

bool CPEDirImport::GetProcInfo(unsigned int lib_id, unsigned int proc_id, PPEImportProcElem proc_struct)
{
	list<Import_Library>::iterator it_lib;
	list<Import_Procedure>::iterator it_proc;

	if (!FindLib(lib_id, it_lib)) {
		return false;
	}

	if (!FindProc(proc_id, it_lib, it_proc)) {
		return false;
	}

	CopyProcElem(proc_struct, &*it_proc);
	return true;
}

bool CPEDirImport::GetFirstLib(PPEImportLibElem lib_struct)
{
	if (_libs.size() == 0) {
		_active_enum_lib = false;
		return false;
	}

	_enum_lib = _libs.begin();
	_active_enum_lib = true;

	CopyLibElem(lib_struct, &*_enum_lib);
	return true;
}

bool CPEDirImport::GetNextLib(PPEImportLibElem lib_struct)
{
	if (!_active_enum_lib) {
		return false;
	}

	_enum_lib++;
	if (_enum_lib == _libs.end()) {
		_active_enum_lib = false;
		return false;
	}

	CopyLibElem(lib_struct, &*_enum_lib);
	return true;
}

bool CPEDirImport::GetFirstProc(unsigned int lib_id, PPEImportProcElem proc_struct)
{
	if (!FindLib(lib_id, _enum_proc_lib)) {
		_active_enum_proc = false;
		return false;
	}

	if (_enum_proc_lib->proc.size() == 0) {
		_active_enum_proc = false;
		return false;
	}

	_enum_proc = _enum_proc_lib->proc.begin();
	_active_enum_proc = true;

	CopyProcElem(proc_struct, &*_enum_proc);
	return true;
}

bool CPEDirImport::GetNextProc(PPEImportProcElem proc_struct)
{
	if (!_active_enum_proc) {
		return false;
	}

	_enum_proc++;
	if (_enum_proc == _enum_proc_lib->proc.end()) {
		_active_enum_proc = false;
		return false;
	}

	CopyProcElem(proc_struct, &*_enum_proc);
	return true;
}

void CPEDirImport::SortLibs()
{
	_libs.sort(sort_libs);
}

bool CPEDirImport::FindLib(unsigned int lib_id, list<Import_Library>::iterator &lib_it)
{
	lib_it = _libs.begin();
	while (lib_it != _libs.end()) {
		if (lib_id == lib_it->lib_id) {
			return true;
		}
		lib_it++;
	}
	return false;
}

bool CPEDirImport::FindProc(unsigned int proc_id, list<Import_Library>::iterator &lib_it, list<Import_Procedure>::iterator &proc_it)
{
	proc_it = lib_it->proc.begin();
	while (proc_it != lib_it->proc.end()) {
		if (proc_it->proc_id == proc_id) {
			return true;
		}
		proc_it++;
	}
	return false;
}

unsigned int CPEDirImport::GenGuid()
{
	return _guid++;
}

void CPEDirImport::ClearEnums()
{
	//_enum_proc_lib = _enum_lib = _libs.end();
	_active_enum_proc = _active_enum_lib = false;
}

void CPEDirImport::CopyLibElem(PPEImportLibElem dest, PPEImportLibElem src)
{
	dest->name = src->name;
	dest->offset_iat = src->offset_iat;
	dest->offset_lookup = src->offset_lookup;
}

void CPEDirImport::CopyProcElem(PPEImportProcElem dest, PPEImportProcElem src)
{
	dest->hint = src->hint;
	dest->inx = src->inx;
	dest->name = src->name;
	dest->ordinal = src->ordinal;
	dest->use_ordinal = src->use_ordinal;
}