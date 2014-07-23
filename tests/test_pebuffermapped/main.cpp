// TODO
// - Add custom test-stub-library (loading through LoadLibrary)
// - Add check_equal checks for custom library

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
#include "PEInfoParser.h"
#include <Windows.h>

using namespace Monstra;

uint32_t img_size = 0x10000;

BOOST_AUTO_TEST_CASE( test1_open_img )
{
	PEBufferMapped mapped(GetModuleHandle(NULL));
	PEMap map;

	//open
	BOOST_CHECK( mapped.Parse() );
	BOOST_CHECK( mapped.IsParsed() );
	BOOST_CHECK( mapped.GetHeader().IsParsed() );
	//close
	mapped.Clear();
	BOOST_CHECK( !mapped.IsParsed() );
	BOOST_CHECK( !mapped.GetHeader().IsParsed() );
	//reopen
	BOOST_CHECK( mapped.Parse() );
	BOOST_CHECK( mapped.IsParsed() );
	BOOST_CHECK( mapped.GetHeader().IsParsed() );

	BOOST_CHECK( mapped.GetMap(map) );
	img_size = map.CalcVirtualSize();
}

BOOST_AUTO_TEST_CASE( test2_conv_to_ptr )
{
	PEBufferMapped mapped(GetModuleHandle(NULL), img_size);
	PEMap map;
	PEBuffer peptr;

	BOOST_CHECK( mapped.Parse() );

	BOOST_CHECK( mapped.GetHeader().ParseMap(map) );
	map.push_back(PEBlockEntry(PE_MAP_SECTOR, 0, 0x2000, 0x2000, 0x400, 0x600));
	BOOST_CHECK( mapped.SetMap(map) );

	BOOST_CHECK( mapped.ConvRawToPtr(peptr, 0x400, 0x200) );
	BOOST_CHECK( mapped.NextRawToPtr(peptr) );

	BOOST_CHECK( !mapped.NextRawToPtr(peptr) );
	BOOST_CHECK( !mapped.ConvRawToPtr(peptr, 0x300, 0x200) );

	BOOST_CHECK( mapped.ConvRvaToPtr(peptr, 0x1000, 0x2000) );
	BOOST_CHECK( mapped.ConvRvaToPtr(peptr, 0x800, 0x800) );
	BOOST_CHECK( !mapped.ConvRvaToPtr(peptr, 0x800, 0x801) );

	BOOST_CHECK( mapped.GetExpectedRawBlock(peptr, 0x300, 0x200) );
	BOOST_CHECK( !mapped.NextExpectedRawBlock(peptr) );

	BOOST_CHECK( mapped.GetExpectedRvaBlock(peptr, 0xf00, 0x200) );
	BOOST_CHECK( mapped.GetExpectedRvaBlock(peptr, 0x2000, 0x10000) );
}