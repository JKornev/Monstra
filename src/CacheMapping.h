#ifndef __PECACHEMNGR_H
#define __PECACHEMNGR_H

#include "PEDefs.h"
#include <Windows.h>
#include <vector>


typedef bool (*_page_walk_callback)(DWORD offset, void *buffer, unsigned int size, void *param);

class CCacheMapping {
private:
	bool _is_allocated;

	unsigned int _aligm;
	unsigned int _pages;
	unsigned int _pages_peak;
	
	void *_region_base;
	std::vector<bool> _region_map;

	_page_walk_callback _callback_load;
	void *_callback_load_param;

	_page_walk_callback _callback_unload;
	void *_callback_unload_param;

	void *GetAndCheckMappedData(DWORD offset, unsigned int size);
	void *GetAndRenewMappedData(DWORD offset, unsigned int size);
	bool FlushAndCheckMappedData(DWORD offset, unsigned int size);

public:
	CCacheMapping();
	~CCacheMapping();

	/*��������������� ������ ��� �����������*/
	bool AllocRegion(unsigned int size);
	/*����������������� ������ ��� �����������,
		* ��� ���������� �������� ������ ������ ����������
		* ��� ���������� ��������� ����������� */
	bool ReallocRegion(unsigned int size);
	/*����������� ������ � �������*/
	void DestroyRegion();

	/*����������� �������-����������� ������������ ��������*/
	bool RegDataLoadingCallback(_page_walk_callback callback, void *param);
	/*����������� �������-����������� ������������ ��������*/
	bool RegDataUnloadingCallback(_page_walk_callback callback, void *param);

	unsigned int GetRegionAligment();	//������ ������������ ����������� ��������
	unsigned int GetRegionSize();		//������ �������
	unsigned int GetRegionPeakSize();	//������� ������ �������

	/*�������� �������� ��� ��������*/
	bool AssignPages(DWORD offset, unsigned int size, void *buf);
	/*�������� ��� �������� ������� ��� ��������*/
	bool AssignAllPages();
	/*�������� �������� ��� ��������*/
	bool UnassignPages(DWORD offset, unsigned int size);
	/*�������� �������� ��� ��������*/
	bool UnassignAllPages();

	/*�������� ��������� �� ���� ������ � ��������� �� ���� ����������*/
	void *GetMappedData(DWORD offset, unsigned int size);
	/*�������� ��������� �� ��� ������ � ��������� �� ���� ����������*/
	void *GetAllMappedData();

	/*�������� ��� ��������� ������*/
	void *RenewMappedData(DWORD offset, unsigned int size);
	/*�������� ��� ��������� ��� ������*/
	void *RenewAllMappedData();

	/*��������� ������ � ��������*/
	bool FlushMappedData(DWORD offset, unsigned int size);
	/*��������� ��� ������ � ��������*/
	bool FlushAllMappedData();

	/*Mb TODEL*/
	/*bool FillEmptyPages(DWORD offset, unsigned int size, _page_walk_callback callback, void *param);
	bool RenewWorkedPages(DWORD offset, unsigned int size, _page_walk_callback callback, void *param);
	bool FlushWorkedPages(DWORD offset, unsigned int size, _page_walk_callback callback, void *param);*/
};

#endif