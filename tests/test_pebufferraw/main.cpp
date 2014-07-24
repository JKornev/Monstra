#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
#include "PEInfoParser.h"
#include "../shared/tools.h"

using namespace Monstra;

uint32_t img_size = 0x1000;

BOOST_AUTO_TEST_CASE( test1_open_img )
{
	std::vector<char> buf;
	PEMap map;

	BOOST_CHECK ( LoadRawBin("../test_bin/test_ms_x86.dll", buf) );

	//parse
	PEBufferRaw raw(&buf[0], buf.size());
	BOOST_CHECK( raw.IsParsed() );

	const PEHeaderParser& parser = raw.GetHeader();
	BOOST_CHECK( parser.IsParsed() );

	//open
	BOOST_CHECK( raw.Parse() );
	BOOST_CHECK( raw.IsParsed() );
	BOOST_CHECK( raw.GetHeader().IsParsed() );
	//close
	raw.Clear();
	BOOST_CHECK( !raw.IsParsed() );
	BOOST_CHECK( !raw.GetHeader().IsParsed() );
	//reopen
	BOOST_CHECK( raw.Parse() );
	BOOST_CHECK( raw.IsParsed() );
	BOOST_CHECK( raw.GetHeader().IsParsed() );

	BOOST_CHECK( raw.GetMap(map) );
	img_size = map.CalcVirtualSize();
}

BOOST_AUTO_TEST_CASE( test2_conv_to_ptr )
{
	std::vector<char> buf;
	PEMap map;
	PEBuffer peptr;

	BOOST_CHECK ( LoadRawBin("../test_bin/test_ms_x86.dll", buf) );

	//parse
	PEBufferRaw raw(&buf[0], buf.size());
	BOOST_CHECK( raw.IsParsed() );

	BOOST_CHECK( raw.GetHeader().ParseMap(map) );
	map.push_back(PEBlockEntry(PE_MAP_SECTOR, 0, 0x2000, 0x2000, 0x400, 0x600));
	BOOST_CHECK( raw.SetMap(map) );

	//conv raw to ptr
	BOOST_CHECK( raw.ConvRawToPtr(peptr, 0x400, 0x200) );
	BOOST_CHECK_EQUAL( peptr.offset(), 0x400 );
	BOOST_CHECK_EQUAL( peptr.size(), 0x200 );
	BOOST_CHECK( !raw.NextRawToPtr(peptr) );

	BOOST_CHECK( !raw.ConvRawToPtr(peptr, 0x300, 0x200) );

	BOOST_CHECK( raw.ConvRawToPtr(peptr, 0x300, 0x100) );
	BOOST_CHECK_EQUAL( peptr.offset(), 0x300 );
	BOOST_CHECK_EQUAL( peptr.size(), 0x100 );

	//conv rva to ptr
	BOOST_CHECK( raw.ConvRvaToPtr(peptr, 0x10000, 0x2000) );
	BOOST_CHECK_EQUAL( peptr.offset(), 0x400 );
	BOOST_CHECK_EQUAL( peptr.size(), 0x2000 );

	BOOST_CHECK( !raw.ConvRvaToPtr(peptr, 0x800, 0x800) );

	BOOST_CHECK( raw.ConvRvaToPtr(peptr, 0x300, 0x100) );
	BOOST_CHECK_EQUAL( peptr.offset(), 0x300 );
	BOOST_CHECK_EQUAL( peptr.size(), 0x100 );

	//get expected raw block
	BOOST_CHECK( raw.GetExpectedRawBlock(peptr, 0x300, 0x200) );
	BOOST_CHECK_EQUAL( peptr.offset(), 0x300 );
	BOOST_CHECK_EQUAL( peptr.size(), 0x100 );
	BOOST_CHECK( !raw.NextExpectedRawBlock(peptr) );

	BOOST_CHECK( raw.GetExpectedRawBlock(peptr, 0x500, 0x200) );
	BOOST_CHECK_EQUAL( peptr.offset(), 0x500 );
	BOOST_CHECK_EQUAL( peptr.size(), 0x200 );

	//get expected rva block
	BOOST_CHECK( raw.GetExpectedRvaBlock(peptr, 0x200, 0x300) );
	BOOST_CHECK_EQUAL( peptr.offset(), 0x200 );
	BOOST_CHECK_EQUAL( peptr.size(), 0x200 );

	BOOST_CHECK( raw.GetExpectedRvaBlock(peptr, 0x11000, 0xE5A00) );
	BOOST_CHECK_EQUAL( peptr.offset(), 0x1400 );
	BOOST_CHECK_EQUAL( peptr.size(), 0xD4A00 );
}