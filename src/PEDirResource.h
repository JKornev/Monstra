#ifndef __PEDIRRESOURCE_H
#define __PEDIRRESOURCE_H

#include "PEDefs.h"
#include "PEInfo.h"
#include "PEManager.h"
#include "PEBuffer.h"


class CPEDirResource {
private:
	

public:
	CPEDirResource();
	~CPEDirResource();

	bool LoadDir(IPEManager *pmngr, DWORD dir_offset = 0);
	bool LoadDirBuffer(void *pbuf, unsigned int size);

	bool AddDir(unsigned int *pdir_id);
	bool RemoveDir(unsigned int dir_id);
	bool RemoveDirsFromEntry(unsigned int entry_id);
	void RemoveAllDirs();

	bool AddEntry(unsigned int dir_id, unsigned int *pentry_id);
	bool RemoveEntry(unsigned int entry_id);

	bool AddData(unsigned int entry_id);

};

#endif