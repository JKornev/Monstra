#include "PEExportHook.h"
#include <vector>


CPEExportHook::CPEExportHook() : _attached(false), _pdir(NULL)
{
}

CPEExportHook::~CPEExportHook()
{
	Detach();
}

bool CPEExportHook::Attach(HMODULE hmod, DWORD dir_offset, IPEManager *psource)
{
	CPEInfo info;
	PIMAGE_DATA_DIRECTORY pdir;
	bool custom_dir = false;

	if (_attached) {
		return false;
	}

	_hmod = hmod;

	if (dir_offset == 0) {
		if (!info.ParseHeader(_hmod)) {
			return false;
		}

		pdir = &info.GetHDataDir()[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!pdir->VirtualAddress || !pdir->Size) {
			return true;//not found OK
		}

		dir_offset = pdir->VirtualAddress;
	} else {
		custom_dir = true;
	}

	_pdescr = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)_hmod + dir_offset);

	if (psource) {
		if (!psource->ReadVirtualData(dir_offset, &_descr, sizeof(IMAGE_EXPORT_DIRECTORY))) {
			return false;
		}

		try {
			_pdir = new CPEDirExport();
		} catch (...) {
			return false;
		}

		if (!_pdir->LoadDir(psource, (custom_dir ? dir_offset : 0)) || !_pdir->RecalcIndexes()) {
			delete _pdir;
			return false;
		}
	} else {
		_pdir = NULL;
		memcpy(&_descr, _pdescr, sizeof(IMAGE_EXPORT_DIRECTORY));
	}

	if (_descr.NumberOfFunctions == 0) {
		delete _pdir;
		return false;
	}

	_pfuncs = (PDWORD)((uintptr_t)_hmod + _descr.AddressOfFunctions);
	if (_descr.NumberOfNames != 0) {
		if (_descr.AddressOfNameOrdinals == 0 || _descr.AddressOfNames == 0) {
			delete _pdir;
			return false;
		}
		_pnames = (PDWORD)((uintptr_t)_hmod + _descr.AddressOfNames);
		_pords = (PWORD)((uintptr_t)_hmod + _descr.AddressOfNameOrdinals);
	} else {
		_pords = NULL;
		_pnames = NULL;
	}

	return _attached = true;
}

void CPEExportHook::Detach()
{
	//RestoreEAT();
	if (_pdir) {
		delete _pdir;
	}
	_attached = false;
}

bool CPEExportHook::IsAttached()
{
	return _attached;
}

bool CPEExportHook::IsLoadedDir()
{
	if (!_attached) {
		return false;
	}
	return (_pdir ? true : false);
}

bool CPEExportHook::SetProcHook(unsigned short ordinal, DWORD voffset)
{
	list<Export_Hook>::iterator it = _hook.begin();
	vector<bool> vused;

	if (!_attached) {
		return false;
	}

	ordinal -= (unsigned short)_descr.Base;
	if (ordinal >= _descr.NumberOfFunctions) {
		return false;
	}

	if (FindHook(ordinal, it)) {
		return false;
	}

	if (_pdir) {
		unsigned int id;
		PEExportProcElem elem;
		if (_pdir->GetProcId(ordinal, &id) && _pdir->GetProcInfo(id, &elem)) {
			AddHook(&_pfuncs[elem.inx], voffset, elem.inx, (elem.use_name ? (char *)elem.name.c_str() : NULL));
			return true;
		}
	} else {
		vused.insert(vused.begin(), _descr.NumberOfFunctions, false);
		
		//named import hook
		for (unsigned int i = 0; i < _descr.NumberOfNames; i++) {
			if (_pords[i] == ordinal) {
				AddHook(&_pfuncs[_pords[i]], voffset, ordinal, (char *)((uintptr_t)_hmod + _pnames[i]));
				return true;
			}
			if (_pords[i] < _descr.NumberOfFunctions) {
				vused[_pords[i]] = true;
			}
		}

		//unnamed import hook
		for (unsigned int i = 0, inx = 0; i < _descr.NumberOfFunctions; i++) {
			if (vused[i]) {
				continue;
			}
			if (inx == ordinal) {
				AddHook(&_pfuncs[i], voffset, ordinal, NULL);
				return true;
			}
			inx++;
		}
	}

	return false;
}

bool CPEExportHook::SetProcHook(char *proc_name, DWORD voffset)
{
	list<Export_Hook>::iterator it = _hook.begin();
	char *pname;
	if (!_attached) {
		return false;
	}

	if (FindHook(proc_name, it)) {
		return false;
	}

	if (_pdir) {
		unsigned int id;
		PEExportProcElem elem;
		if (_pdir->GetProcId(proc_name, &id) && _pdir->GetProcInfo(id, &elem)) {
			AddHook(&_pfuncs[elem.inx], voffset, elem.inx, proc_name);
			return true;
		}
	} else {
		//named import hook
		for (unsigned int i = 0; i < _descr.NumberOfNames; i++) {
			pname = (char *)((uintptr_t)_hmod + _pnames[i]);
			if (!strcmp(pname, proc_name)) {
				AddHook(&_pfuncs[_pords[i]], voffset, _pords[i], pname);
				return true;
			}
		}
	}

	return false;
}

bool CPEExportHook::RestoreProcHook(unsigned short ordinal)
{
	list<Export_Hook>::iterator it = _hook.begin();
	if (!_attached) {
		return false;
	}

	if (!FindHook(ordinal, it)) {
		return false;
	}

	SetValueWithAccess<DWORD>(it->pvalue, it->orig_val);
	_hook.erase(it);
	return true;
}

bool CPEExportHook::RestoreProcHook(char *proc_name)
{
	list<Export_Hook>::iterator it = _hook.begin();
	if (!_attached) {
		return false;
	}

	if (!FindHook(proc_name, it)) {
		return false;
	}

	SetValueWithAccess<DWORD>(it->pvalue, it->orig_val);
	_hook.erase(it);
	return true;
}

bool CPEExportHook::RestoreEAT()
{
	list<Export_Hook>::iterator it = _hook.begin();
	if (!_attached) {
		return false;
	}
	while (it != _hook.end()) {
		SetValueWithAccess<DWORD>(it->pvalue, it->orig_val);
		it++;
	}
	_hook.clear();
	return true;
}

bool CPEExportHook::ConvPtr32ToOffset(void *ptr, DWORD *pvoffset)
{
	if (!_attached) {
		return false;
	}
	//this is works only for 32bit pointers
	if (sizeof(DWORD) != sizeof(void *)) {
		return false;
	}
	*pvoffset = (DWORD)ptr - (DWORD)_hmod;
	return true;
}

unsigned int CPEExportHook::ChecksumEAT()
{
	unsigned int checksum;
	if (!_attached) {
		return 0;
	}
	checksum = checksum32(_pdescr, sizeof(IMAGE_EXPORT_DIRECTORY));
	checksum ^= checksum32(_pfuncs, _descr.NumberOfFunctions * sizeof(DWORD));
	checksum ^= checksum32(_pnames, _descr.NumberOfNames * sizeof(DWORD));
	checksum ^= checksum32(_pords, _descr.NumberOfNames * sizeof(WORD));
	return checksum;
}

bool CPEExportHook::IssetProc(unsigned short ordinal, unsigned int *pinx)
{
	if (!_attached) {
		return false;
	}

	ordinal -= (unsigned short)_descr.Base;
	if (ordinal >= _descr.NumberOfFunctions) {
		return false;
	}

	if (_pdir) {
		unsigned int id;
		PEExportProcElem elem;

		if (_pdir->GetProcId(ordinal, &id) && _pdir->GetProcInfo(id, &elem)) {//founded
			if (pinx) {
				*pinx = elem.inx;
			}
			return true;
		}
	} else {
		vector<bool> vused;
		vused.insert(vused.begin(), _descr.NumberOfFunctions, false);

		//named import hook
		for (unsigned int i = 0; i < _descr.NumberOfNames; i++) {
			if (_pords[i] == ordinal) {
				if (pinx) {
					*pinx = i;
				}
				return true;
			}
			if (_pords[i] < _descr.NumberOfFunctions) {
				vused[_pords[i]] = true;
			}
		}

		//unnamed import hook
		for (unsigned int i = 0, inx = 0; i < _descr.NumberOfFunctions; i++) {
			if (vused[i]) {
				continue;
			}
			if (inx == ordinal) {
				if (pinx) {
					*pinx = i;
				}
				return true;
			}
			inx++;
		}
	}

	return false;
}

bool CPEExportHook::IssetProc(char *proc_name, unsigned int *pinx)
{
	if (!_attached) {
		return false;
	}

	if (_pdir) {
		unsigned int id;
		PEExportProcElem elem;
		if (_pdir->GetProcId(proc_name, &id) && _pdir->GetProcInfo(id, &elem)) {//founded
			if (pinx) {
				*pinx = elem.inx;
			}
			return true;
		}
	} else {
		char *pname;
		for (unsigned int i = 0; i < _descr.NumberOfNames; i++) {
			pname = (char *)((uintptr_t)_hmod + _pnames[i]);
			if (!strcmp(proc_name, pname)) {
				if (pinx) {
					*pinx = i;
				}
				return true;
			}
		}
	}

	return false;
}

bool CPEExportHook::EnumProcs(enum_exp_procs_callback callback, void *param)
{
	if (!_attached) {
		return false;
	}

	if (_pdir) {
		PEExportProcElem elem;
		if (!_pdir->GetFirstProc(&elem)) {
			return false;
		}
		do {
			if (!callback((elem.use_name ? elem.name.c_str() : NULL), _pfuncs[elem.inx], 
			(unsigned short)(elem.inx + _descr.Base), param)) {
				return false;
			}
		} while (_pdir->GetNextProc(&elem));
	} else {
		vector<bool> vused;
		char *pname;

		vused.insert(vused.begin(), _descr.NumberOfFunctions, false);

		//enum named
		for (unsigned int i = 0; i < _descr.NumberOfNames; i++) {
			pname = (char *)((uintptr_t)_hmod + _pnames[i]);
			if (!callback(pname, _pfuncs[_pords[i]], _pords[i] + (unsigned short)_descr.Base, param)) {
				return false;
			}
			if (_pords[i] < _descr.NumberOfFunctions) {
				vused[_pords[i]] = true;
			}
		}
		//enum unnamed
		for (unsigned int i = 0, inx = 0; i < _descr.NumberOfFunctions; i++) {
			if (vused[i]) {
				continue;
			}
			if (!callback(NULL, _pfuncs[i], (unsigned short)(i + _descr.Base), param)) {
				return false;
			}
		}
	}

	return true;
}

bool CPEExportHook::FindHook(char *proc_name, list<Export_Hook>::iterator &it)
{
	while (it != _hook.end()) {
		if (it->name_used && !strcmp(proc_name, it->proc_name.c_str())) {
			return true;
		}
		it++;
	}
	return false;
}

bool CPEExportHook::FindHook(unsigned short ordinal, list<Export_Hook>::iterator &it)
{
	while (it != _hook.end()) {
		if (ordinal == it->ordinal) {
			return true;
		}
		it++;
	}
	return false;
}

void CPEExportHook::AddHook(DWORD *pvalue, DWORD new_value, unsigned short ordinal, char *proc_name)
{
	Export_Hook hook;

	hook.pvalue = pvalue;
	hook.orig_val = *pvalue;
	hook.ordinal = ordinal;
	hook.proc_name = proc_name;
	hook.name_used = (proc_name ? true : false);
	SetValueWithAccess<DWORD>(pvalue, new_value);
	_hook.push_back(hook);
}