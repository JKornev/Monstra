#ifndef __PEDIREXPORT_H
#define __PEDIREXPORT_H

#include "PEDefs.h"
#include "PEInfo.h"
#include "PEManager.h"
#include "PEBuffer.h"
#include <list>
#include <string>

using namespace std;


typedef struct _PEExportProcElem {
	bool use_name;
	unsigned short ordinal;
	string name;
	DWORD offset;
	int inx;
} PEExportProcElem, *PPEExportProcElem;


class CPEDirExport {
private:
	struct Export_Procedure : public PEExportProcElem {
		int proc_id;
	};

	int _guid;
	int _max_inx;

	list<Export_Procedure> _proc;

	bool _active_enum_proc;
	list<Export_Procedure>::iterator _enum_proc;

	inline unsigned int GenGuid();

	bool FindProc(unsigned int proc_id, list<Export_Procedure>::iterator &proc_it);

	inline void CopyProcElem(PPEExportProcElem dest, PPEExportProcElem src);

public:
	CPEDirExport();
	~CPEDirExport();

	bool LoadDir(IPEManager *pmngr, DWORD dir_offset = 0);

	bool AddProc(char *proc_name, unsigned short ordinal, DWORD offset, unsigned int *proc_id, int inx = -1);
	bool AddProc(DWORD offset, unsigned int *proc_id, int inx = -1);
	bool RemoveProc(unsigned int proc_id);
	void RemoveAllProcs();

	unsigned int GetProcCount();
	bool GetProcId(char *proc_name, unsigned int *proc_id);
	bool GetProcId(unsigned short ordinal, unsigned int *proc_id);
	bool GetProcId(char *proc_name, unsigned short ordinal, unsigned int *proc_id);
	bool GetProcId(DWORD offset, unsigned int *proc_id);
	bool GetProcInfo(unsigned int proc_id, PPEExportProcElem proc_struct);

	//Enum procs
	bool GetFirstProc(PPEExportProcElem proc_struct);
	bool GetNextProc(PPEExportProcElem proc_struct);

	bool RecalcIndexes();
	void UnsetUnnamedIndexes();

	//TODO build
};

#endif