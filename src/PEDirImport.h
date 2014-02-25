#ifndef __PEDIRIMPORT_H
#define __PEDIRIMPORT_H

#include "PEDefs.h"
#include "PEInfo.h"
#include "PEManager.h"
#include "PEBuffer.h"
#include <string>
#include <list>

using namespace std;


typedef struct _PEImportProcElem {
	string name;
	bool use_ordinal;
	unsigned short hint;
	unsigned short ordinal;
	int inx;
} PEImportProcElem, *PPEImportProcElem;

typedef struct _PEImportLibElem {
	string name;
	DWORD offset_lookup;
	DWORD offset_iat;
} PEImportLibElem, *PPEImportLibElem;


class CPEDirImport {
private:
	struct Import_Procedure : public PEImportProcElem {
		int proc_id;
	};

	struct Import_Library : public PEImportLibElem {
		int lib_id;
		int order;
		list<Import_Procedure> proc;
	};

	int _guid;

	bool _merge_if_exist;
	bool _active_enum_lib;
	bool _active_enum_proc;

	list<Import_Library> _libs;

	list<Import_Library>::iterator _find_lib;
	list<Import_Procedure>::iterator _find_proc;

	list<Import_Library>::iterator _enum_lib;
	list<Import_Procedure>::iterator _enum_proc;
	list<Import_Library>::iterator _enum_proc_lib;

	inline unsigned int GenGuid();
	void ClearEnums();

	bool FindLib(unsigned int lib_id, list<Import_Library>::iterator &lib_it);
	bool FindProc(unsigned int proc_id, list<Import_Library>::iterator &lib_it, list<Import_Procedure>::iterator &proc_it);
	
	inline void CopyLibElem(PPEImportLibElem dest, PPEImportLibElem src);
	inline void CopyProcElem(PPEImportProcElem dest, PPEImportProcElem src);

	template<typename T>
	inline int LoadLookupTable(IPEManager *pmngr, DWORD roffset, unsigned int count, 
		unsigned int buf_len, unsigned int lib_id, CPEBuffer &buf);

	static bool sort_libs(Import_Library &lib_a, Import_Library &lib_b)
	{
		return lib_a.order < lib_b.order;
	}

public:
	CPEDirImport(bool merge_mode = false);
	~CPEDirImport();

	bool LoadDir(IPEManager *pmngr, DWORD dir_offset = 0, bool error_on_iat_merge = false);

	void AddLib(char *lib_name, int order, unsigned int *lib_id);
	bool RemoveLib(unsigned int lib_id);
	void RemoveAllLibs();
	bool SetLibOffset(unsigned int lib_id, DWORD lookup, DWORD iat);

	bool AddProcByName(unsigned int lib_id, char *proc_name, unsigned short hint, unsigned int *proc_id, int inx = -1);
	bool AddProcByOrdinal(unsigned int lib_id, unsigned short ordinal, unsigned int *proc_id, int inx = -1);
	bool RemoveProc(unsigned int lib_id, unsigned int proc_id);
	bool RemoveAllProc(unsigned int lib_id);

	bool GetLibId(char *lib_name, unsigned int *lib_id);
	bool GetProcId(unsigned int lib_id, char *proc_name, unsigned int *proc_id);
	bool GetProcId(unsigned int lib_id, unsigned short ordinal, unsigned int *proc_id);

	unsigned int GetLibCount();
	unsigned int GetProcCount(unsigned int lib_id);

	bool GetLibInfo(unsigned int lib_id, PPEImportLibElem lib_struct);
	bool GetProcInfo(unsigned int lib_id, unsigned int proc_id, PPEImportProcElem proc_struct);

	//Enum libs
	bool GetFirstLib(PPEImportLibElem lib_struct);
	bool GetNextLib(PPEImportLibElem lib_struct);
	//Enum procs
	bool GetFirstProc(unsigned int lib_id, PPEImportProcElem proc_struct);
	bool GetNextProc(PPEImportProcElem proc_struct);

	void SortLibs();

	/*unsigned int GetDirSize();
	bool BuildDir(void *pbuf, unsigned int size, unsigned int *pdir_size, DWORD offset);*/
};

#endif