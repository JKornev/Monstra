#ifndef __PEIMPORTHOOK_H
#define __PEIMPORTHOOK_H

#include "PEDefs.h"
#include "PEInfo.h"
#include "PEManager.h"
#include "PEDirImport.h"
#include <Windows.h>
#include <list>
#include <string>

using namespace std;


typedef bool (*enum_imp_libs_callback)(const char *lib_name, void *param);
typedef bool (*enum_imp_procs_callback)(const char *lib_name, bool use_ordinal,
	unsigned short ordinal, const char *proc_name, void *param);

class CPEImportHook {
private:
	struct Import_Hook {
		uintptr_t *pvalue;
		uintptr_t orig_value;
		string lib_name;
		bool use_ordinal;
		unsigned short ordinal;
		string proc_name;
	};

	bool _attached;
	bool _merged;

	HMODULE _hmod;

	PIMAGE_IMPORT_DESCRIPTOR _pdescr;
	DWORD _descr_count;

	CPEDirImport *_pdir;

	list<Import_Hook> _hook;

	bool FindHook(char *lib_name, char *proc_name, list<Import_Hook>::iterator &hook_it);
	bool FindHook(char *lib_name, unsigned short ordinal, list<Import_Hook>::iterator &hook_it);

public:
	CPEImportHook();
	~CPEImportHook();

//Open import
	bool Attach(HMODULE hmod, DWORD dir_offset = 0, IPEManager *psource = NULL);
	void Detach();

	inline bool IsAttached();
	bool IsLoadedDir();
	bool IsIATMerged();

//Hook API
	bool SetProcHook(char *lib_name, char *proc_name, void *hook_proc);
	bool SetProcHook(char *lib_name, unsigned short ordinal, void *hook_proc);
	bool RestoreProcHook(char *lib_name, char *proc_name);
	bool RestoreProcHook(char *lib_name, unsigned short ordinal);
	bool RestoreIAT();

//Import info
	unsigned int ChecksumIAT();

	bool IssetLib(char *lib_name);
	bool IssetProc(char *lib_name, char *proc_name);
	bool IssetProc(char *lib_name, unsigned short ordinal);

	bool EnumLibs(enum_imp_libs_callback callback, void *param);
	bool EnumProcs(char *lib_name, enum_imp_procs_callback callback, void *param);

	unsigned int GetLibDublicateCount(char *lib_name);
	unsigned int GetProcDublicateCount(char *lib_name, char *proc_name);
	unsigned int GetProcDublicateCount(char *lib_name, unsigned short ordinal);
};

#endif