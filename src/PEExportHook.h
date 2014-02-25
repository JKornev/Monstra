#ifndef __PEEXPORTHOOK_H
#define __PEEXPORTHOOK_H

#include "PEDefs.h"
#include "PEInfo.h"
#include "PEManager.h"
#include "PEDirExport.h"
#include <list>
#include <string>

using namespace std;


typedef bool (*enum_exp_procs_callback)(const char *proc_name, DWORD offset, unsigned short ordinal, void *param);

class CPEExportHook {
private:
	struct Export_Hook {
		DWORD orig_val;
		DWORD *pvalue;
		bool name_used;
		unsigned short ordinal;
		string proc_name;
	};

	bool _attached;

	HMODULE _hmod;
	IMAGE_EXPORT_DIRECTORY _descr;

	PIMAGE_EXPORT_DIRECTORY _pdescr;
	PDWORD _pfuncs;
	PDWORD _pnames;
	PWORD _pords;

	CPEDirExport *_pdir;

	list<Export_Hook> _hook;

	bool FindHook(char *proc_name, list<Export_Hook>::iterator &it);
	bool FindHook(unsigned short ordinal, list<Export_Hook>::iterator &it);

	inline void AddHook(DWORD *pvalue, DWORD new_value, unsigned short ordinal, char *proc_name);

public:
	CPEExportHook();
	~CPEExportHook();

//Open export
	bool Attach(HMODULE hmod, DWORD dir_offset = 0, IPEManager *psource = NULL);
	void Detach();

	inline bool IsAttached();
	bool IsLoadedDir();

//Hook API
	bool SetProcHook(unsigned short ordinal, DWORD voffset);
	bool SetProcHook(char *proc_name, DWORD voffset);

	bool RestoreProcHook(unsigned short ordinal);
	bool RestoreProcHook(char *proc_name);
	bool RestoreEAT();

	bool ConvPtr32ToOffset(void *ptr, DWORD *pvoffset);

//Export info
	unsigned int ChecksumEAT();

	bool IssetProc(unsigned short ordinal, unsigned int *pinx = NULL);
	bool IssetProc(char *proc_name, unsigned int *pinx = NULL);

	bool GetProcInfo(unsigned int inx, PPEExportProcElem proc_struct);

	bool EnumProcs(enum_exp_procs_callback callback, void *param);
};

#endif