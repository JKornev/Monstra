#include "PEImportHook.h"


CPEImportHook::CPEImportHook() : _attached(false), _merged(false), _pdir(NULL), _descr_count(0)
{
}

CPEImportHook::~CPEImportHook()
{
	Detach();
}

bool CPEImportHook::Attach(HMODULE hmod, DWORD dir_offset, IPEManager *psource)
{
	CPEInfo info;
	PIMAGE_DATA_DIRECTORY pdir;
	PIMAGE_IMPORT_DESCRIPTOR pdescr;
	bool custom_dir = false;

	if (_attached) {
		return false;
	}

	_hmod = hmod;

	if (dir_offset == 0) {
		if (!info.ParseHeader(_hmod)) {
			return false;
		}

		pdir = &info.GetHDataDir()[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!pdir->VirtualAddress || !pdir->Size) {
			return true;//not found OK
		}

		dir_offset = pdir->VirtualAddress;
	} else {
		custom_dir = true;
	}
	
	pdescr = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)_hmod + dir_offset);
	for (_descr_count = 0; pdescr[_descr_count].Name; _descr_count++) {
		if (!_merged && (!pdescr[_descr_count].OriginalFirstThunk 
		|| pdescr[_descr_count].FirstThunk == pdescr[_descr_count].OriginalFirstThunk)) {
			_merged = true;
		}
	}
	if (_merged && !psource) {//merged import must have advance info from second container
		return false;
	}

	if (/*_merged && */psource) {//fix, _dir loading enable without merged-mode
		if (!psource->IsOpened() || psource->IsRuntimeObject()) {
			return false;
		}
		try {
			_pdir = new CPEDirImport;
			_pdescr = new IMAGE_IMPORT_DESCRIPTOR[_descr_count];
		} catch (...) {
			return false;
		}
		if (!psource->ReadVirtualData(dir_offset, _pdescr, _descr_count * sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			Detach();
			return false;
		}
		if (!_pdir->LoadDir(psource, (custom_dir ? dir_offset : 0))) {
			Detach();
			return false;
		}
	} else {
		try {
			_pdescr = new IMAGE_IMPORT_DESCRIPTOR[_descr_count];
		} catch (...) {
			return false;
		}
		memcpy(_pdescr, pdescr, _descr_count * sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

	return _attached = true;
}

void CPEImportHook::Detach()
{
	//RestoreIAT();
	if (_pdir) {
		delete _pdir;
		_pdir = NULL;
	}
	if (_pdescr) {
		delete[] _pdescr;
		_pdescr = NULL;
	}
	_attached = false;
}

bool CPEImportHook::IsAttached()
{
	return _attached;
}

bool CPEImportHook::IsLoadedDir()
{
	if (!_attached) {
		return false;
	}
	return (_pdir ? true : false);
}

bool CPEImportHook::IsIATMerged()
{
	if (!_attached) {
		return false;
	}
	return _merged;
}

bool CPEImportHook::SetProcHook(char *lib_name, char *proc_name, void *hook_proc)
{
	list<Import_Hook>::iterator it = _hook.begin();
	unsigned int lib_id, proc_id;
	PEImportLibElem lib_elem;
	PEImportProcElem proc_elem;
	Import_Hook hook;
	unsigned int hooks_count = 0;
	char *str;

	if (!_attached) {
		return false;
	}

	if (FindHook(lib_name, proc_name, it)) {
		return false;
	}

	hook.use_ordinal = false;
	hook.ordinal = 0;
	hook.lib_name = lib_name;

	if (/*_merged*/_pdir) {//Import data are being searched from the import container
		while (_pdir->GetLibId(lib_name, &lib_id)) {
			lib_name = NULL;//for enum lib
			if (!_pdir->GetLibInfo(lib_id, &lib_elem)) {
				return false;
			}

			str = proc_name;
			while (_pdir->GetProcId(lib_id, str, &proc_id)) {
				str = NULL;//for enum proc
				if (!_pdir->GetProcInfo(lib_id, proc_id, &proc_elem)) {
					return false;
				}

				hook.proc_name = proc_name;
				hook.pvalue = (uintptr_t *)((uintptr_t)_hmod + lib_elem.offset_iat + (sizeof(uintptr_t) * proc_elem.inx));
				hook.orig_value = *hook.pvalue;

				//*hook.pvalue = (uintptr_t)hook_proc;//TODO mb reaccess
				SetValueWithAccess<uintptr_t>(hook.pvalue, (uintptr_t)hook_proc);

				_hook.push_back(hook);
				hooks_count++;
			}
		}
	} else {//Import data are being searched from descriptors
		PIMAGE_IMPORT_BY_NAME pname;
		PIMAGE_THUNK_DATA pthunk;

		for (unsigned int i = 0; i < _descr_count; i++) {
			str =(char *)((uintptr_t)_hmod + _pdescr[i].Name);
			if (_strcmpi(str, lib_name) != 0) {
				continue;
			}

			pthunk = (PIMAGE_THUNK_DATA)((uintptr_t)_hmod + _pdescr[i].OriginalFirstThunk);
			for (unsigned int a = 0; pthunk[a].u1.AddressOfData; a++) {
				if (pthunk[a].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					continue;
				}

				pname = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)_hmod + pthunk[a].u1.AddressOfData);
				if (!strcmp(proc_name, (char *)pname->Name)) {
					hook.proc_name = proc_name;
					hook.pvalue = (uintptr_t *)((uintptr_t)_hmod + _pdescr[i].FirstThunk + (sizeof(uintptr_t) * a));
					hook.orig_value = *hook.pvalue;

					//*hook.pvalue = (uintptr_t)hook_proc;//TODO mb reaccess
					SetValueWithAccess<uintptr_t>(hook.pvalue, (uintptr_t)hook_proc);

					_hook.push_back(hook);
					hooks_count++;
				}
			}
		}
	}
	if (hooks_count == 0) {
		return false;
	}
	return true;
}

bool CPEImportHook::SetProcHook(char *lib_name, unsigned short ordinal, void *hook_proc)
{
	list<Import_Hook>::iterator it = _hook.begin();
	unsigned int lib_id, proc_id;
	PEImportLibElem lib_elem;
	PEImportProcElem proc_elem;
	Import_Hook hook;
	unsigned int hooks_count = 0;
	unsigned short ord;

	if (!_attached) {
		return false;
	}

	if (FindHook(lib_name, ordinal, it)) {
		return false;
	}

	hook.use_ordinal = true;
	hook.lib_name = lib_name;

	if (/*_merged*/_pdir) {//Import data are being searched from the import container
		while (_pdir->GetLibId(lib_name, &lib_id)) {
			lib_name = NULL;//for enum lib
			if (!_pdir->GetLibInfo(lib_id, &lib_elem)) {
				return false;
			}

			ord = ordinal;
			while (_pdir->GetProcId(lib_id, ord, &proc_id)) {
				ord = -1;//for enum proc
				if (!_pdir->GetProcInfo(lib_id, proc_id, &proc_elem)) {
					return false;
				}

				hook.ordinal = ordinal;
				hook.pvalue = (uintptr_t *)((uintptr_t)_hmod + lib_elem.offset_iat + (sizeof(uintptr_t) * proc_elem.inx));
				hook.orig_value = *hook.pvalue;

				//*hook.pvalue = (uintptr_t)hook_proc;//TODO mb reaccess
				SetValueWithAccess<uintptr_t>(hook.pvalue, (uintptr_t)hook_proc);

				_hook.push_back(hook);
				hooks_count++;
			}
		}
	} else {//Import data are being searched from descriptors
		PIMAGE_THUNK_DATA pthunk;
		char *str;

		for (unsigned int i = 0; i < _descr_count; i++) {
			str =(char *)((uintptr_t)_hmod + _pdescr[i].Name);
			if (_strcmpi(str, lib_name) != 0) {
				continue;
			}

			pthunk = (PIMAGE_THUNK_DATA)((uintptr_t)_hmod + _pdescr[i].OriginalFirstThunk);
			for (unsigned int a = 0; pthunk[a].u1.AddressOfData; a++) {
				if (!(pthunk[a].u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
					continue;
				}

				ord = (unsigned short)pthunk[a].u1.Ordinal;
				if (ord == ordinal) {
					hook.ordinal = ordinal;
					hook.pvalue = (uintptr_t *)((uintptr_t)_hmod + _pdescr[i].FirstThunk + (sizeof(uintptr_t) * a));
					hook.orig_value = *hook.pvalue;

					//*hook.pvalue = (uintptr_t)hook_proc;//TODO mb reaccess
					SetValueWithAccess<uintptr_t>(hook.pvalue, (uintptr_t)hook_proc);

					_hook.push_back(hook);
					hooks_count++;
				}
			}
		}
	}
	if (hooks_count == 0) {
		return false;
	}
	return true;
}

bool CPEImportHook::RestoreProcHook(char *lib_name, char *proc_name)
{
	list<Import_Hook>::iterator it = _hook.begin(), it_remove;
	unsigned int rem_count = 0;
	if (!_attached) {
		return false;
	}

	while (FindHook(lib_name, proc_name, it)) {//TOTEST iterators
		it_remove = it;
		it++;

		//*it_remove->pvalue = it_remove->orig_value;
		SetValueWithAccess<uintptr_t>(it_remove->pvalue, (uintptr_t)it_remove->orig_value);
		_hook.erase(it_remove);

		rem_count++;
	}

	return (rem_count != 0 ? true : false);
}

bool CPEImportHook::RestoreProcHook(char *lib_name, unsigned short ordinal)
{
	list<Import_Hook>::iterator it = _hook.begin(), it_remove;
	unsigned int rem_count = 0;
	if (!_attached) {
		return false;
	}

	while (FindHook(lib_name, ordinal, it)) {//TOTEST iterators
		it_remove = it;
		it++;

		//*it_remove->pvalue = it_remove->orig_value;
		SetValueWithAccess<uintptr_t>(it_remove->pvalue, (uintptr_t)it_remove->orig_value);
		_hook.erase(it_remove);

		rem_count++;
	}

	return (rem_count != 0 ? true : false);
}

bool CPEImportHook::RestoreIAT()
{
	list<Import_Hook>::iterator it = _hook.begin();
	if (!_attached) {
		return false;
	}
	while (it != _hook.end()) {//TODO mb reaccess
		//*it->pvalue = it->orig_value;
		SetValueWithAccess<uintptr_t>(it->pvalue, (uintptr_t)it->orig_value);
		it++;
	}
	_hook.clear();
	return true;
}

unsigned int CPEImportHook::ChecksumIAT()
{
	unsigned int checksum;
	uintptr_t *pvalue;
	if (!_attached) {
		return 0;
	}
	
	checksum = checksum32(_pdescr, sizeof(IMAGE_IMPORT_DESCRIPTOR) * _descr_count);
	for (unsigned int i = 0, a = 0; i < _descr_count; i++) {
		pvalue = (uintptr_t *)((uintptr_t)_hmod + _pdescr[i].FirstThunk);
		for (a = 0; pvalue[a]; a++);

		checksum ^= checksum32(pvalue, sizeof(uintptr_t) * a);
	}
	return checksum;
}

bool CPEImportHook::IssetLib(char *lib_name)
{
	char *str;
	unsigned int lib_id;
	if (!_attached) {
		return false;
	}

	if (/*_merged*/_pdir) {
		if (_pdir->GetLibId(lib_name, &lib_id)) {
			return true;
		}
	} else {
		for (unsigned int i = 0; i < _descr_count; i++) {
			str =(char *)((uintptr_t)_hmod + _pdescr[i].Name);
			if (!_strcmpi(str, lib_name)) {
				return true;
			}
		}
	}
	return false;
}

bool CPEImportHook::IssetProc(char *lib_name, char *proc_name)
{
	char *str;
	PIMAGE_IMPORT_BY_NAME pname;
	PIMAGE_THUNK_DATA pthunk;
	unsigned int lib_id, proc_id;

	if (!_attached) {
		return false;
	}
	
	if (/*_merged*/_pdir) {
		if (!_pdir->GetLibId(lib_name, &lib_id)) {
			return false;
		}
		if (_pdir->GetProcId(lib_id, proc_name, &proc_id)) {
			return true;
		}
	} else {
		for (unsigned int i = 0; i < _descr_count; i++) {
			str =(char *)((uintptr_t)_hmod + _pdescr[i].Name);
			if (_strcmpi(str, lib_name) != 0) {
				continue;
			}

			pthunk = (PIMAGE_THUNK_DATA)((uintptr_t)_hmod + _pdescr[i].OriginalFirstThunk);
			for (unsigned int a = 0; pthunk[a].u1.AddressOfData; a++) {
				if (pthunk[a].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					continue;
				}

				pname = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)_hmod + pthunk[a].u1.AddressOfData);
				if (!strcmp(proc_name, (char *)pname->Name)) {
					return true;
				}
			}
		}
	}
	return false;
}

bool CPEImportHook::IssetProc(char *lib_name, unsigned short ordinal)
{
	char *str;
	PIMAGE_THUNK_DATA pthunk;
	unsigned int lib_id, proc_id;

	if (!_attached) {
		return false;
	}

	if (/*_merged*/_pdir) {
		if (!_pdir->GetLibId(lib_name, &lib_id)) {
			return false;
		}
		if (_pdir->GetProcId(lib_id, ordinal, &proc_id)) {
			return true;
		}
	} else {
		for (unsigned int i = 0; i < _descr_count; i++) {
			str =(char *)((uintptr_t)_hmod + _pdescr[i].Name);
			if (_strcmpi(str, lib_name) != 0) {
				continue;
			}

			pthunk = (PIMAGE_THUNK_DATA)((uintptr_t)_hmod + _pdescr[i].OriginalFirstThunk);
			for (unsigned int a = 0; pthunk[a].u1.AddressOfData; a++) {
				if (!(pthunk[a].u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
					continue;
				}

				if ((unsigned short)(pthunk[a].u1.Ordinal ^ IMAGE_ORDINAL_FLAG) == ordinal) {
					return true;
				}
			}
		}
	}
	return false;
}

bool CPEImportHook::EnumLibs(enum_imp_libs_callback callback, void *param)
{
	if (!_attached) {
		return false;
	}

	if (_pdir) {
		PEImportLibElem elem;
		if (!_pdir->GetFirstLib(&elem)) {
			return false;
		}
		do {
			if (!callback(elem.name.c_str(), param)) {
				return false;
			}
		} while (_pdir->GetNextLib(&elem));
	} else {
		char *str;
		for (unsigned int i = 0; i < _descr_count; i++) {
			str = (char *)((uintptr_t)_hmod + _pdescr[i].Name);
			if (!callback(str, param)) {
				return false;
			}
		}
	}

	return true;
}

bool CPEImportHook::EnumProcs(char *lib_name, enum_imp_procs_callback callback, void *param)
{
	if (!_attached) {
		return false;
	}

	if (_pdir) {
		PEImportProcElem proc_elem;
		unsigned int lib_id;

		if (!_pdir->GetLibId(lib_name, &lib_id)) {
			return false;
		}
		do {
			_pdir->GetFirstProc(lib_id, &proc_elem);
			do {
				if (!callback(lib_name, proc_elem.use_ordinal, proc_elem.ordinal, proc_elem.name.c_str(), param)) {
					return false;
				}
			} while (_pdir->GetNextProc(&proc_elem));
		} while (_pdir->GetLibId(NULL, &lib_id));
	} else {
		char *str, *str2;
		PIMAGE_THUNK_DATA pthunk;
		bool use_ordinal;
		unsigned short ordinal = 0;

		for (unsigned int i = 0; i < _descr_count; i++) {
			str = (char *)((uintptr_t)_hmod + _pdescr[i].Name);
			if (_strcmpi(str, lib_name)) {
				continue;
			}

			pthunk = (PIMAGE_THUNK_DATA)((uintptr_t)_hmod + _pdescr[i].OriginalFirstThunk);
			for (unsigned int a = 0; pthunk[a].u1.AddressOfData; a++) {
				if (pthunk[a].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					use_ordinal = true;
					ordinal = (unsigned short)pthunk[a].u1.Ordinal;
				} else {
					use_ordinal = false;
					str2 = (char *)((uintptr_t)_hmod + pthunk[a].u1.AddressOfData + 2);
				}

				if (!callback(lib_name, use_ordinal, ordinal, str2, param)) {
					return false;
				}
			}
		}
	}

	return true;
}

unsigned int CPEImportHook::GetLibDublicateCount(char *lib_name)
{
	char *str;
	unsigned int count = 0;
	if (!_attached) {
		return 0;
	}
	for (unsigned int i = 0; i < _descr_count; i++) {
		str = (char *)((uintptr_t)_hmod + _pdescr[i].Name);
		if (!_strcmpi(lib_name, str)) {
			count++;
		}
	}
	return count;
}

unsigned int CPEImportHook::GetProcDublicateCount(char *lib_name, char *proc_name)
{
	char *str, *str2;
	PIMAGE_THUNK_DATA pthunk;
	unsigned int count = 0;

	if (!_attached) {
		return 0;
	}

	for (unsigned int i = 0; i < _descr_count; i++) {
		str = (char *)((uintptr_t)_hmod + _pdescr[i].Name);
		if (_strcmpi(str, lib_name) != 0) {
			continue;
		}

		pthunk = (PIMAGE_THUNK_DATA)((uintptr_t)_hmod + _pdescr[i].OriginalFirstThunk);
		for (unsigned int a = 0; pthunk[a].u1.AddressOfData; a++) {
			if (pthunk[a].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				continue;
			}
			str2 = (char *)((uintptr_t)_hmod + pthunk[a].u1.AddressOfData + 2);
			if (!strcmp(str2, proc_name)) {
				count++;
			}
		}
	}
	return count;
}

unsigned int CPEImportHook::GetProcDublicateCount(char *lib_name, unsigned short ordinal)
{
	char *str;
	PIMAGE_THUNK_DATA pthunk;
	unsigned int count = 0;
	unsigned short ord;

	if (!_attached) {
		return 0;
	}

	for (unsigned int i = 0; i < _descr_count; i++) {
		str = (char *)((uintptr_t)_hmod + _pdescr[i].Name);
		if (_strcmpi(str, lib_name) != 0) {
			continue;
		}

		pthunk = (PIMAGE_THUNK_DATA)((uintptr_t)_hmod + _pdescr[i].OriginalFirstThunk);
		for (unsigned int a = 0; pthunk[a].u1.AddressOfData; a++) {
			if (!(pthunk[a].u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
				continue;
			}
			ord = (unsigned short)pthunk[a].u1.Ordinal;
			if (ord == ordinal) {
				count++;
			}
		}
	}
	return count;
}

bool CPEImportHook::FindHook(char *lib_name, char *proc_name, list<Import_Hook>::iterator &hook_it)
{
	while (hook_it != _hook.end()) {
		if (hook_it->use_ordinal) {
			continue;
		}
		if (!_strcmpi(lib_name, hook_it->lib_name.c_str()) && !strcmp(proc_name, hook_it->proc_name.c_str())) {
			return true;
		}
		hook_it++;
	}
	return false;
}

bool CPEImportHook::FindHook(char *lib_name, unsigned short ordinal, list<Import_Hook>::iterator &hook_it)
{
	while (hook_it != _hook.end()) {
		if (!hook_it->use_ordinal) {
			continue;
		}
		if (ordinal == hook_it->ordinal) {
			return true;
		}
		hook_it++;
	}
	return false;
}