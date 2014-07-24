#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
#include "PEInfoParser.h"
#include "../shared/tools.h"

using namespace Monstra;

BOOST_AUTO_TEST_CASE( test1_parsing_pe32 )
{
	std::vector<char> buf;

	BOOST_CHECK ( LoadRawBin("../test_bin/test_ms_x86.dll", buf) );

	//parse
	PEBufferRaw raw(&buf[0], buf.size());
	BOOST_CHECK( raw.IsParsed() );

	PEHeaderParser& parser = raw.GetHeader();
	BOOST_CHECK( parser.IsParsed() );

	//check ptrs
	BOOST_CHECK( !parser.GetDos().is_empty() );
	BOOST_CHECK( !parser.GetImg().is_empty() );
	BOOST_CHECK( !parser.GetOpt32().is_empty() );
	BOOST_CHECK( parser.GetOpt64().is_empty() );
	BOOST_CHECK( !parser.GetDataDir().is_empty() );
	BOOST_CHECK( !parser.GetHeader32().is_empty() );
	BOOST_CHECK( parser.GetHeader64().is_empty() );
	
	//check values
	BOOST_CHECK_EQUAL( parser.GetArch(), PE_32 );
	BOOST_CHECK_EQUAL( parser.GetImg()->TimeDateStamp, 0x521EA8E7);
	BOOST_CHECK_EQUAL( parser.GetOpt32()->ImageBase, 0x7DE70000);
	BOOST_CHECK_EQUAL( parser.GetDataDir()[MONSTRA_PE_IMG_DIR_ENTRY_EXPORT].VirtualAddress, 0x000101E8);
	BOOST_CHECK_EQUAL( parser.GetHeader32()->Signature, MONSTRA_PE_IMG_NT_SIGNATURE);

	BOOST_CHECK( parser.HaveDataDir(MONSTRA_PE_IMG_DIR_ENTRY_RESOURCE) );
	BOOST_CHECK( !parser.HaveDataDir(MONSTRA_PE_IMG_DIR_ENTRY_IMPORT) );

	BOOST_CHECK_EQUAL( parser.GetVirtualAlignment(), 0x10000 );
	BOOST_CHECK_EQUAL( parser.GetRawAlignment(), 0x200 );

	BOOST_CHECK_EQUAL( parser.GetHeaderSize(), 0x00000400 );

	BOOST_CHECK_EQUAL( parser.FindFirstSectorPosByName(".data"), 2);
	BOOST_CHECK_EQUAL( parser.FindFirstSectorPosByName(".sdata"), MONSTRA_PE_INVALID_SECTOR);

	BOOST_CHECK_EQUAL( parser.FindFirstSectorPosByRaw(0x000DCF00), 3);
	BOOST_CHECK_EQUAL( parser.FindFirstSectorPosByRaw(buf.size()), MONSTRA_PE_INVALID_SECTOR);

	BOOST_CHECK_EQUAL( parser.FindSectorPosByVirtual(0x00111000), 3);
	BOOST_CHECK_EQUAL( parser.FindSectorPosByVirtual(0x001A9000), MONSTRA_PE_INVALID_SECTOR);

	std::vector<int> positions;
	positions.push_back(4);
	BOOST_CHECK( parser.FindSectorPosByName("RT", positions) );
	BOOST_CHECK_EQUAL( positions.size(), 1);
	BOOST_CHECK_EQUAL( positions[0], 1);

	BOOST_CHECK( parser.FindSectorPosByRaw(0x000DCF00, positions) );
	BOOST_CHECK_EQUAL( positions.size(), 1);
	BOOST_CHECK_EQUAL( positions[0], 3);
	
	//closing
	parser.Clear();
	BOOST_CHECK( !parser.IsParsed() );

	BOOST_CHECK( parser.GetDos().is_empty() );
	BOOST_CHECK( parser.GetImg().is_empty() );
	BOOST_CHECK( parser.GetOpt32().is_empty() );
	BOOST_CHECK( parser.GetOpt64().is_empty() );
	BOOST_CHECK( parser.GetDataDir().is_empty() );
	BOOST_CHECK( parser.GetHeader32().is_empty() );
	BOOST_CHECK( parser.GetHeader64().is_empty() );
}

BOOST_AUTO_TEST_CASE( test1_parsing_pe64 )
{
	std::vector<char> buf;

	BOOST_CHECK ( LoadRawBin("../test_bin/test_ms_x64.dll", buf) );

	//parse
	PEBufferRaw raw(&buf[0], buf.size());
	BOOST_CHECK( raw.IsParsed() );

	PEHeaderParser& parser = raw.GetHeader();
	BOOST_CHECK( parser.IsParsed() );

	//check ptrs
	BOOST_CHECK( !parser.GetDos().is_empty() );
	BOOST_CHECK( !parser.GetImg().is_empty() );
	BOOST_CHECK( parser.GetOpt32().is_empty() );
	BOOST_CHECK( !parser.GetOpt64().is_empty() );
	BOOST_CHECK( !parser.GetDataDir().is_empty() );
	BOOST_CHECK( parser.GetHeader32().is_empty() );
	BOOST_CHECK( !parser.GetHeader64().is_empty() );

	//check values
	BOOST_CHECK_EQUAL( parser.GetArch(), PE_64 );
	BOOST_CHECK_EQUAL( parser.GetImg()->TimeDateStamp, 0x521EAF24);
	BOOST_CHECK_EQUAL( parser.GetOpt64()->ImageBase, 0x0000000078E50000);
	BOOST_CHECK_EQUAL( parser.GetDataDir()[MONSTRA_PE_IMG_DIR_ENTRY_EXPORT].VirtualAddress, 0x00106270);
	BOOST_CHECK_EQUAL( parser.GetHeader64()->Signature, MONSTRA_PE_IMG_NT_SIGNATURE);

	BOOST_CHECK( parser.HaveDataDir(MONSTRA_PE_IMG_DIR_ENTRY_RESOURCE) );
	BOOST_CHECK( !parser.HaveDataDir(MONSTRA_PE_IMG_DIR_ENTRY_IMPORT) );

	BOOST_CHECK_EQUAL( parser.GetVirtualAlignment(), 0x1000 );
	BOOST_CHECK_EQUAL( parser.GetRawAlignment(), 0x200 );

	BOOST_CHECK_EQUAL( parser.GetHeaderSize(), 0x00000400 );

	BOOST_CHECK_EQUAL( parser.FindFirstSectorPosByName(".rdata"), 2);
	BOOST_CHECK_EQUAL( parser.FindFirstSectorPosByName(".sdata"), MONSTRA_PE_INVALID_SECTOR);

	BOOST_CHECK_EQUAL( parser.FindFirstSectorPosByRaw(0x0012Fb00), 3);
	BOOST_CHECK_EQUAL( parser.FindFirstSectorPosByRaw(buf.size()), MONSTRA_PE_INVALID_SECTOR);

	BOOST_CHECK_EQUAL( parser.FindSectorPosByVirtual(0x00133000), 3);
	BOOST_CHECK_EQUAL( parser.FindSectorPosByVirtual(0x001A9000), MONSTRA_PE_INVALID_SECTOR);

	std::vector<int> positions;
	positions.push_back(4);
	BOOST_CHECK( parser.FindSectorPosByName("RT", positions) );
	BOOST_CHECK_EQUAL( positions.size(), 1);
	BOOST_CHECK_EQUAL( positions[0], 1);

	BOOST_CHECK( parser.FindSectorPosByRaw(0x0012Fb00, positions) );
	BOOST_CHECK_EQUAL( positions.size(), 1);
	BOOST_CHECK_EQUAL( positions[0], 3);

	//closing
	parser.Clear();
	BOOST_CHECK( !parser.IsParsed() );

	BOOST_CHECK( parser.GetDos().is_empty() );
	BOOST_CHECK( parser.GetImg().is_empty() );
	BOOST_CHECK( parser.GetOpt32().is_empty() );
	BOOST_CHECK( parser.GetOpt64().is_empty() );
	BOOST_CHECK( parser.GetDataDir().is_empty() );
	BOOST_CHECK( parser.GetHeader32().is_empty() );
	BOOST_CHECK( parser.GetHeader64().is_empty() );
}
