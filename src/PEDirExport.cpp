#include "PEDirExport.h"
#include <algorithm>


CPEDirExport::CPEDirExport() : _guid(0), _max_inx(0)
{
}

CPEDirExport::~CPEDirExport()
{
	RemoveAllProcs();
}

bool CPEDirExport::LoadDir(IPEManager *pmngr, DWORD dir_offset)
{
	enum { ProcNameLen = 25 };
	PIMAGE_DATA_DIRECTORY pdir_descr;
	IMAGE_EXPORT_DIRECTORY exp;
	DWORD roffset, *pnames = NULL, *pfuncs = NULL;
	unsigned short *pords = NULL;
	CPEBuffer buf(pmngr);
	char *pname;
	unsigned int buf_len, block_size, len, id;

	if (!pmngr->IsOpened()) {
		return false;
	}

	if (!dir_offset) {
		pdir_descr = &pmngr->GetHDataDir()[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!pdir_descr->VirtualAddress || !pdir_descr->Size) {
			return true;//not found OK
		}
		dir_offset = pdir_descr->VirtualAddress;
	}

	if (!pmngr->ReadVirtualData(dir_offset, &exp, sizeof(exp)) || exp.NumberOfFunctions == 0) {
		return false;
	}
	
	try {
		pfuncs = new DWORD[exp.NumberOfFunctions];
		if (exp.NumberOfNames > 0) {
			pnames = new DWORD[exp.NumberOfNames];
			pords = new unsigned short[exp.NumberOfNames];
		}

		if (!pmngr->ReadVirtualData(exp.AddressOfFunctions, pfuncs, exp.NumberOfFunctions * sizeof(DWORD))) {
			throw;
		}
		if (!pmngr->ReadVirtualData(exp.AddressOfNames, pnames, exp.NumberOfNames * sizeof(DWORD))) {
			throw;
		}
		if (!pmngr->ReadVirtualData(exp.AddressOfNameOrdinals, pords, exp.NumberOfNames * sizeof(WORD))) {
			throw;
		}

		//named export load
		for (unsigned int i = 0; i < exp.NumberOfNames; i++) {
			//name loading
			buf_len = ProcNameLen;
			if (pmngr->ConvVirtualToRaw(pnames[i], &roffset, &block_size) == PE_MAP_OUT_OF_RANGE || block_size < 3) {
				throw;
			}
			if (buf_len > block_size) {
				buf_len = block_size;
			}
			do {
				pname = (char *)buf.GetRawDataBlock(roffset, buf_len);
				if (!pname) {
					throw;
				}

				if (!IsZeroEndStr(pname, buf_len, len)) {//try read more data
					if (buf_len == block_size) {
						throw;//can't load more data
					}

					buf_len += ProcNameLen;
					if (buf_len > block_size) {
						buf_len = block_size;
					}

					buf.FreeDataBlock(pname);
				} else {
					break;
				}
			} while (true);
			//fixed pfuncs index
			if (!AddProc(pname, pords[i], pfuncs[pords[i]], &id, pords[i])) {
				buf.FreeDataBlock(pname);
				continue;//error missing
			}
			buf.FreeDataBlock(pname);
		}

		//unnamed export load
		for (unsigned int i = exp.NumberOfNames; i < exp.NumberOfFunctions; i++) {
			AddProc(pfuncs[i], &id, -1);
		}

	} catch (...) {
		if (pfuncs) {
			delete[] pfuncs;
		}
		if (pnames) {
			delete[] pnames;
		}
		if (pords) {
			delete[] pords;
		}
		return false;
	}

	delete[] pfuncs;
	delete[] pnames;
	delete[] pords;
	return true;
}

bool CPEDirExport::AddProc(char *proc_name, unsigned short ordinal, DWORD offset, unsigned int *proc_id, int inx)
{
	Export_Procedure proc;
	unsigned int id;

	if (GetProcId(proc_name, ordinal, &id)) {
		return false;
	}

	if (inx < -1) {
		inx = -1;
	}

	proc.proc_id = GenGuid();
	proc.use_name = true;
	proc.name = proc_name;
	proc.ordinal = ordinal;
	proc.offset = offset;
	proc.inx = inx;
	_proc.push_back(proc);

	if (inx >= 0 && inx > _max_inx) {
		_max_inx = inx;
	}

	*proc_id = proc.proc_id;
	return true;
}

bool CPEDirExport::AddProc(DWORD offset, unsigned int *proc_id, int inx)
{
	Export_Procedure proc;
	//unsigned int id;
	/*TODEL this check not need (named conflict is missed)
	if (GetProcId(offset, &id)) {
		return false;
	}*/

	if (inx < -1) {
		inx = -1;
	}

	proc.proc_id = GenGuid();
	proc.use_name = false;
	proc.ordinal = -1;
	proc.offset = offset;
	proc.inx = inx;
	_proc.push_back(proc);

	if (inx >= 0 && inx > _max_inx) {
		_max_inx = inx;
	}

	*proc_id = proc.proc_id;
	return true;
}

bool CPEDirExport::RemoveProc(unsigned int proc_id)
{
	list<Export_Procedure>::iterator it = _proc.begin();
	if (!FindProc(proc_id, it)) {
		return false;
	}
	_proc.erase(it);
	if (_proc.size() == 0) {
		_max_inx = 0;
	}
	return true;
}

void CPEDirExport::RemoveAllProcs()
{
	_max_inx = 0;
	_proc.clear();
}

unsigned int CPEDirExport::GetProcCount()
{
	return _proc.size();
}

bool CPEDirExport::GetProcId(char *proc_name, unsigned int *proc_id)
{
	list<Export_Procedure>::iterator it = _proc.begin();
	while (it != _proc.end()) {
		if (it->use_name && !strcmp(proc_name, it->name.c_str())) {
			*proc_id = it->proc_id;
			return true;
		}
		it++;
	}
	return false;
}

bool CPEDirExport::GetProcId(unsigned short ordinal, unsigned int *proc_id)
{
	list<Export_Procedure>::iterator it = _proc.begin();
	while (it != _proc.end()) {
		if (it->use_name && ordinal == it->ordinal) {
			*proc_id = it->proc_id;
			return true;
		}
		it++;
	}
	return false;
}

bool CPEDirExport::GetProcId(char *proc_name, unsigned short ordinal, unsigned int *proc_id)
{
	list<Export_Procedure>::iterator it = _proc.begin();
	while (it != _proc.end()) {
		if (it->use_name && ordinal == it->ordinal && !strcmp(proc_name, it->name.c_str())) {
			*proc_id = it->proc_id;
			return true;
		}
		it++;
	}
	return false;
}

bool CPEDirExport::GetProcId(DWORD offset, unsigned int *proc_id)
{
	list<Export_Procedure>::iterator it = _proc.begin();
	while (it != _proc.end()) {
		if (it->offset == offset) {
			*proc_id = it->proc_id;
			return true;
		}
		it++;
	}
	return false;
}

bool CPEDirExport::GetProcInfo(unsigned int proc_id, PPEExportProcElem proc_struct)
{
	list<Export_Procedure>::iterator it = _proc.begin();
	if (!FindProc(proc_id, it)) {
		return false;
	}
	CopyProcElem(proc_struct, &*it);
	return true;
}

bool CPEDirExport::GetFirstProc(PPEExportProcElem proc_struct)
{
	if (_proc.size() == 0) {
		_active_enum_proc = false;
		return false;
	}

	_enum_proc = _proc.begin();
	_active_enum_proc = true;

	CopyProcElem(proc_struct, &*_enum_proc);
	return true;
}

bool CPEDirExport::GetNextProc(PPEExportProcElem proc_struct)
{
	if (!_active_enum_proc) {
		return false;
	}

	_enum_proc++;
	if (_enum_proc == _proc.end()) {
		_active_enum_proc = false;
		return false;
	}

	CopyProcElem(proc_struct, &*_enum_proc);
	return true;
}

//RecalcIndexes misc
struct _Recalc_Elem {
	int *ptr;
	int inx;
};

class find_pred_class {
	int _inx;
public:
	find_pred_class(int inx) {_inx = inx;}
	bool operator() (_Recalc_Elem *pelem)
	{
		return (pelem->inx == _inx);
	}
};

bool CPEDirExport::RecalcIndexes()
{//TOFIX возможно, при совпадающих name_ord неправильное повидение
	list<Export_Procedure>::iterator it;
	unsigned int proc_count = _proc.size(), unnamed_count = 0;
	_Recalc_Elem *pelems, *pelem;
	list<_Recalc_Elem *> lfree, lused;
	list<_Recalc_Elem *>::iterator it_lfree, it_lused;

	if (proc_count == 0) {
		return true;
	}

	if ((unsigned int)_max_inx < proc_count - 1) {
		_max_inx = proc_count - 1;
	}

	try {
		pelems = new _Recalc_Elem[_max_inx + 1];
	} catch (...) {
		return false;
	}

	for (int i = 0; i <= _max_inx; i++) {
		pelems[i].inx = i;
		pelems[i].ptr = NULL;
		lfree.push_back(&pelems[i]);
	}

	//named export is recalculated
	it = _proc.begin();
	for (unsigned int i = 0; i < proc_count; i++, it++) {
		if (!it->use_name) {
			unnamed_count++;
			continue;
		}

		pelem = lfree.front();

		if (it->inx == -1) {
			it->inx = pelem->inx;
			pelem->ptr = &it->inx;
			lused.push_back(pelem);
			lfree.pop_front();
		} else {
			//elem.inx = it->inx;
			it_lfree = find_if(lfree.begin(), lfree.end(), find_pred_class(it->inx));
			if (it_lfree != lfree.end()) {//if founded
				pelem = *it_lfree;
				pelem->ptr = &it->inx;
				lused.push_back(pelem);
				lfree.erase(it_lfree);
			} else {
				it_lused = find_if(lused.begin(), lused.end(), find_pred_class(it->inx));
				if (it_lused == lused.end()) {
					delete[] pelems;
					return false;
				}

				_Recalc_Elem *ptemp = *it_lused;
				pelem->ptr = ptemp->ptr;
				*pelem->ptr = pelem->inx;
				ptemp->ptr = &it->inx;
				lused.push_back(pelem);
				lfree.pop_front();
			}
		}
	}

	//unnamed export is recalculated
	it = _proc.begin();
	for (unsigned int i = 0; i < proc_count; i++, it++) {
		if (it->use_name) {
			continue;
		}

		it->inx = (lfree.front())->inx;
		lfree.pop_front();

		unnamed_count--;
		if (unnamed_count == 0) {
			break;
		}
	}

	delete[] pelems;
	return true;
}

void CPEDirExport::UnsetUnnamedIndexes()
{
	list<Export_Procedure>::iterator it = _proc.begin();
	while (it != _proc.end()) {
		if (it->use_name) {
			it++;
			continue;
		}
		it->inx = -1;
		it++;
	}
}

unsigned int CPEDirExport::GenGuid()
{
	return _guid++;
}

bool CPEDirExport::FindProc(unsigned int proc_id, list<Export_Procedure>::iterator &proc_it)
{
	while (proc_it != _proc.end()) {
		if (proc_id == proc_it->proc_id) {
			return true;
		}
		proc_it++;
	}
	return false;
}

void CPEDirExport::CopyProcElem(PPEExportProcElem dest, PPEExportProcElem src)
{
	dest->name = src->name;
	dest->offset = src->offset;
	dest->ordinal = src->ordinal;
	dest->use_name = src->use_name;
	dest->inx = src->inx;
}