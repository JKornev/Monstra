#ifndef __MONSTRA_PE_PARSER_H
#define __MONSTRA_PE_PARSER_H

#include "BaseDefs.h"

namespace Monstra {

class io_ptr_interface;

class PESourceInterface {
public:
	virtual bool ConvRawToPtr(io_ptr_interface& ptr, dword raw, uint32_t size) = 0;
	virtual bool NextRawToPtr(io_ptr_interface& ptr) = 0;
	virtual bool ConvRvaToPtr(io_ptr_interface& ptr, dword rva, uint32_t size) = 0;
	virtual bool GetExpectedRawBlock(io_ptr_interface& ptr, dword raw, uint32_t expected_size) = 0;
	virtual bool NextExpectedRawBlock(io_ptr_interface& ptr) = 0;
	virtual bool GetExpectedRvaBlock(io_ptr_interface& ptr, dword rva, uint32_t expected_size) = 0;
};

};/*Monstra namespace*/

#endif
