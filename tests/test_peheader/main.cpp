#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
#include "PEInfoParser.h"
#include "../shared/tools.h"

using namespace Monstra;

BOOST_AUTO_TEST_CASE( test1_loading_pe32 )
{
	PEBufferRaw raw;
	std::vector<char> buf;

	BOOST_CHECK ( LoadRawBin("../test_bin/test_ms_x86.dll", buf) );

	//parse
	BOOST_CHECK( raw.Parse(&buf[0], buf.size()) );
	BOOST_CHECK( raw.IsParsed() );

	PEHeader header;
	BOOST_CHECK( raw.ParseHeader(header) );
	
	//check data
	PEImgDosHeader dos;
	PEImgNtHeaders32 headers;

	header.GetDos(dos);
	BOOST_CHECK( header.GetHeader32(headers) );

	BOOST_CHECK_EQUAL( header.GetArch(), PE_32 );

	BOOST_CHECK_EQUAL ( dos.e_magic, MONSTRA_PE_IMG_DOS_SIGNATURE );
	BOOST_CHECK_EQUAL ( headers.Signature, MONSTRA_PE_IMG_NT_SIGNATURE );

	BOOST_CHECK_EQUAL( header.GetImgMachine(), headers.FileHeader.Machine );
	BOOST_CHECK_EQUAL( header.GetOptEntryPoint(), headers.OptionalHeader.AddressOfEntryPoint );
}

BOOST_AUTO_TEST_CASE( test1_loading_pe64 )
{
	PEBufferRaw raw;
	std::vector<char> buf;

	BOOST_CHECK ( LoadRawBin("../test_bin/test_ms_x64.dll", buf) );

	//parse
	BOOST_CHECK( raw.Parse(&buf[0], buf.size()) );
	BOOST_CHECK( raw.IsParsed() );

	PEHeader header;
	BOOST_CHECK( raw.ParseHeader(header) );

	//check data
	PEImgDosHeader dos;
	PEImgNtHeaders64 headers;

	header.GetDos(dos);
	BOOST_CHECK( header.GetHeader64(headers) );

	BOOST_CHECK_EQUAL( header.GetArch(), PE_64 );

	BOOST_CHECK_EQUAL ( dos.e_magic, MONSTRA_PE_IMG_DOS_SIGNATURE );
	BOOST_CHECK_EQUAL ( headers.Signature, MONSTRA_PE_IMG_NT_SIGNATURE );

	BOOST_CHECK_EQUAL( header.GetImgMachine(), headers.FileHeader.Machine );
	BOOST_CHECK_EQUAL( header.GetOptEntryPoint(), headers.OptionalHeader.AddressOfEntryPoint );
}
