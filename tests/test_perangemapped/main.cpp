#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
#include "PEInfoParser.h"
#include "PEDirRelocs.h"
#include "../shared/tools.h"

using namespace Monstra;

BOOST_AUTO_TEST_CASE( test1_open_img )
{
	std::vector<char> buf;
	PEMap map;

	BOOST_CHECK ( LoadRawBin("../test_bin/dump_relocs_00170000.bin", buf) );

	//parse
	PERangeMapped range;
	PERelocsParser parser;

	BOOST_CHECK( range.AddRange(&buf[0], 0x00170000, buf.size()) );

	BOOST_CHECK( parser.Parse(&range, 0x00170000, buf.size(), 0ull) );
	BOOST_CHECK( parser.IsParsed() );

	BOOST_CHECK( range.RemoveRange(&buf[0]) );
	BOOST_CHECK( !parser.Parse(&range, 0x00170000, buf.size(), 0ull) );
	BOOST_CHECK( !parser.IsParsed() );
}

