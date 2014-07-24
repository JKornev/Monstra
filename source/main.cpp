#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>
//#include <WinNT.h>
#include "IOPointer.h"
#include "PEInfoParser.h"
#include "PEMap.h"

using namespace std;
using namespace Monstra;

io_manager mngr;
char buf[100] = {1, 2, 3};

class TClass {
public:

	bool ConvRVAToPtr(io_ptr_interface& ptr, dword rva, uint32_t size);
	bool ConvRawToPtr(io_ptr_interface& ptr, dword rva, uint32_t size);
	bool NextRawToPtr(io_ptr_interface& ptr);
};

void test()
{

}

io_ptr<char> test2()
{
	return io_ptr<char>(&mngr, buf, 10, 23);
}

int main()
{
	io_ptr<char> ptr = test2();
	//io_ptr<char> ptr2 = ptr;
	//io_ptr<char> ptr3;

	
	//ptr3 = ptr;
	//ptr = ptr2;

	
	//mngr._attach(ptr);
	cout << "start" << endl;

	PEBufferMapped mapped(GetModuleHandle(NULL), 0x4000);
	PEMap map;
	PEBuffer peptr;


	if (!mapped.Parse()) {
		cout << "error open" << endl;
	}
	/*if (!mapped.Open(GetModuleHandle(NULL), 0x4000)) {
		cout << "error open" << endl;
	}*/

	pPEImgDosHeader pdos = mapped.GetHeader().GetDos().ptr();
	pPEImgFileHeader pimg = mapped.GetHeader().GetImg().ptr();
	pPEImgOptHeader32 popt32 = mapped.GetHeader().GetOpt32().ptr();
	pPEImgOptHeader64 popt64 = mapped.GetHeader().GetOpt64().ptr();
	pPEImgDataDir pdir = mapped.GetHeader().GetDataDir().ptr();
	pPEImgNtHeaders32 pheader32 = mapped.GetHeader().GetHeader32().ptr();
	pPEImgNtHeaders64 pheader64 = mapped.GetHeader().GetHeader64().ptr();

	if (!mapped.GetHeader().ParseMap(map)) {
		cout << "error map parse" << endl;
	}

	map.push_back(PEBlockEntry(PE_MAP_SECTOR, 0, 0x2000, 0x2000, 0x400, 0x600));
	mapped.SetMap(map);

	if (!mapped.ConvRawToPtr(peptr, 0x400, 0x200)) {
		cout << "error conv failed" << endl;
	}
	if (!mapped.NextRawToPtr(peptr)) {
		cout << "error conv failed" << endl;
	}
	if (mapped.NextRawToPtr(peptr)) {
		cout << "error conv failed" << endl;
	}
	if (mapped.ConvRawToPtr(peptr, 0x300, 0x200)) {
		cout << "error conv failed" << endl;
	}

	if (!mapped.ConvRvaToPtr(peptr, 0x1000, 0x2000)) {
		cout << "error conv failed" << endl;
	}
	if (!mapped.ConvRvaToPtr(peptr, 0x800, 0x800)) {
		cout << "error conv failed" << endl;
	}
	if (mapped.ConvRvaToPtr(peptr, 0x800, 0x801)) {
		cout << "error conv failed" << endl;
	}

	if (!mapped.GetExpectedRawBlock(peptr, 0x300, 0x200)) {
		cout << "error ext failed" << endl;
	}
	if (mapped.NextExpectedRawBlock(peptr)) {
		cout << "error ext failed" << endl;
	}

	if (!mapped.GetExpectedRvaBlock(peptr, 0xf00, 0x200)) {
		cout << "error ext failed" << endl;
	}
	if (!mapped.GetExpectedRvaBlock(peptr, 0x2000, 0x10000)) {
		cout << "error ext failed" << endl;
	}

	PEHeaderParser pehead;
	if (!mapped.Parse()) {
		cout << "error ext failed" << endl;
	}

	if (!mapped.ParseHeader(pehead)) {
		cout << "error parse failed" << endl;
	}

	map.Realign(0x2000, 0x400);
	map.Realign(0x1000, 0x200);
	mapped.Clear();



// FILE
	PEBuffer pebuf;
	fstream file("../../tests/test_bin/test_ms_x86.dll", ios_base::in | ios_base::binary);

	if (!file) {
		cout << "Open file error " << endl;
	}

	vector<char> buf;

	file.seekg(0, ios_base::end);
	buf.insert(buf.begin(), static_cast<uint32_t>(file.tellg()), 0);
	file.seekg(0, ios_base::beg);

	file.read(&buf[0], buf.size());
	file.close();

	PEBufferRaw raw(&buf[0], buf.size());

	if (!raw.Parse()) {
		cout << "error open 2" << endl;
	}

	/*if (!raw.ConvRawToPtr(pebuf, 0x1000, 0x200)) {
		cout << "can't convert 1" << endl;
	}
	if (!raw.NextRawToPtr(pebuf)) {
		cout << "can't convert 2" << endl;
	}*/

	if (!raw.GetHeader().ParseMap(map)) {
		cout << "error map parse" << endl;
	}

	map.push_back(PEBlockEntry(PE_MAP_SECTOR, 0, 0x2000, 0x2000, 0x400, 0x600));
	raw.SetMap(map);

	if (!raw.ConvRawToPtr(peptr, 0x400, 0x200)) {
		cout << "error conv failed" << endl;
	}
	if (raw.NextRawToPtr(peptr)) {
		cout << "error conv failed" << endl;
	}
	if (raw.ConvRawToPtr(peptr, 0x300, 0x200)) {
		cout << "error conv failed" << endl;
	}
	if (!raw.ConvRawToPtr(peptr, 0x300, 0x100)) {
		cout << "error conv failed" << endl;
	}

	if (!raw.ConvRvaToPtr(peptr, 0x10000, 0x2000)) {
		cout << "error conv failed" << endl;
	}
	if (raw.ConvRvaToPtr(peptr, 0x800, 0x800)) {
		cout << "error conv failed" << endl;
	}
	if (!raw.ConvRvaToPtr(peptr, 0x300, 0x100)) {
		cout << "error conv failed" << endl;
	}

	if (!raw.GetExpectedRawBlock(peptr, 0x300, 0x200)) {
		cout << "error ext failed" << endl;
	}
	if (raw.NextExpectedRawBlock(peptr)) {
		cout << "error ext failed" << endl;
	}
	if (!raw.GetExpectedRawBlock(peptr, 0x500, 0x200)) {
		cout << "error ext failed" << endl;
	}

	if (!raw.GetExpectedRvaBlock(peptr, 0x200, 0x300)) {
		cout << "error ext failed" << endl;
	}
	if (!raw.GetExpectedRvaBlock(peptr, 0x10000, 0x000E5A00)) {
		cout << "error ext failed" << endl;
	}

	PERangeMapped range;

	cout << "ok" << endl;
	//getchar();
	return 0;
}