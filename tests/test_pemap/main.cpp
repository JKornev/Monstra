#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
#include "PEMap.h"

using namespace Monstra;

PEMap map;

BOOST_AUTO_TEST_CASE( test1_loading_data )
{
	PEMap local_map;
	local_map.push_back(PEBlockEntry(PE_MAP_HEADER, -1, 0, 0x400, 0, 0x250));
	local_map.push_back(PEBlockEntry(PE_MAP_SECTOR,  0, 0x1000, 0x400, 0x550, 0x350));
	local_map.push_back(PEBlockEntry(PE_MAP_SECTOR,  1, 0x2100, 0x1001, 0x800, 0x3000));
	local_map.push_back(PEBlockEntry(PE_MAP_SECTOR,  2, 0x4005, 0x4000, 0x1000, 0x250));
	local_map.push_back(PEBlockEntry(PE_MAP_SECTOR,  3, 0x8000, 0x1000, 0x500, 0x400));
	local_map.Realign(0x1000, 0x200);
	map = local_map;

	BOOST_CHECK(map.GetVirtualAlign() == 0x1000 && map.GetRawAlign() == 0x200);

	//header
	BOOST_CHECK_EQUAL( map[0].rva, 0 );
	BOOST_CHECK_EQUAL( map[0].rva_size, 0x1000 );
	BOOST_CHECK_EQUAL( map[0].raw, 0 );
	BOOST_CHECK_EQUAL( map[0].raw_size, 0x400 );
	//sector1
	BOOST_CHECK_EQUAL( map[1].rva, 0x1000 );
	BOOST_CHECK_EQUAL( map[1].rva_size, 0x1000 );
	BOOST_CHECK_EQUAL( map[1].raw, 0x400 );
	BOOST_CHECK_EQUAL( map[1].raw_size, 0x400 );
	//sector2
	BOOST_CHECK_EQUAL( map[2].rva, 0x2000 );
	BOOST_CHECK_EQUAL( map[2].rva_size, 0x2000 );
	BOOST_CHECK_EQUAL( map[2].raw, 0x800 );
	BOOST_CHECK_EQUAL( map[2].raw_size, 0x2000 );
	//sector3
	BOOST_CHECK_EQUAL( map[3].rva, 0x4000 );
	BOOST_CHECK_EQUAL( map[3].rva_size, 0x4000 );
	BOOST_CHECK_EQUAL( map[3].raw, 0x1000 );
	BOOST_CHECK_EQUAL( map[3].raw_size, 0x400 );
	//sector4
	BOOST_CHECK_EQUAL( map[4].rva, 0x8000 );
	BOOST_CHECK_EQUAL( map[4].rva_size, 0x1000 );
	BOOST_CHECK_EQUAL( map[4].raw, 0x400 );
	BOOST_CHECK_EQUAL( map[4].raw_size, 0x400 );
}

BOOST_AUTO_TEST_CASE( test2_convert )
{
	uint32_t inx;
	std::vector<uint32_t> inxs;
	std::vector<PEBlockEntry> blocks;
	PEBlockEntry entry;

	BOOST_CHECK( map.GetBlockInxByRaw(0x3FF, inxs) && inxs.size() == 1 && inxs[0] == 0 );
	BOOST_CHECK( map.GetBlockInxByRaw(0x400, inxs) && inxs.size() == 2 && inxs[0] == 1 && inxs[1] == 4 );

	BOOST_CHECK( map.GetRelativeBlockByRaw(0x3FF, blocks) && blocks.size() == 1 );
	BOOST_CHECK_EQUAL( blocks[0].rva, 0x3FF );
	BOOST_CHECK_EQUAL( blocks[0].rva_size, 0xC01 );
	BOOST_CHECK_EQUAL( blocks[0].raw, 0x3FF );
	BOOST_CHECK_EQUAL( blocks[0].raw_size, 1 );

	BOOST_CHECK( map.GetBlockInxByRva(0x800, inx) && inx == 0 );
	BOOST_CHECK( map.GetBlockInxByRva(0x3FFF, inx) && inx == 2 );

	BOOST_CHECK( map.GetRelativeBlockByRva(0x4400, entry) );
	BOOST_CHECK_EQUAL( entry.rva, 0x4400 );
	BOOST_CHECK_EQUAL( entry.rva_size, 0x3c00 );
	BOOST_CHECK_EQUAL( entry.raw, 0 );
	BOOST_CHECK_EQUAL( entry.raw_size, 0 );

	BOOST_CHECK( map.GetRelativeBlockByRva(0x8100, entry) );
	BOOST_CHECK_EQUAL( entry.rva, 0x8100 );
	BOOST_CHECK_EQUAL( entry.rva_size, 0xf00 );
	BOOST_CHECK_EQUAL( entry.raw, 0x500 );
	BOOST_CHECK_EQUAL( entry.raw_size, 0x300 );
}

BOOST_AUTO_TEST_CASE( test3_align )
{
	// TODO
}
