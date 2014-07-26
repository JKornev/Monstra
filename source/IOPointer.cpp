#include "IOPointer.h"
#include <exception>

using namespace std;

namespace Monstra {

// ======================= io_ptr_interface =======================

io_ptr_interface::io_ptr_interface(io_manager* mngr, void* ptr, dword offset, uint32_t size) :
	_io_mngr(0),
	_io_ptr(ptr),
	_io_offset(offset),
	_io_size(size)
{
	if (mngr != 0)
		_attach(mngr);
}

io_ptr_interface::io_ptr_interface(const io_ptr_interface& src, dword offset, uint32_t size) :
	_io_mngr(0),
	_io_ptr(0),
	_io_offset(0),
	_io_size(0)
{
	dword src_offset = src.offset();
	uint32_t src_size = src.size();

	if (size == 0 || src_offset > offset || src_offset + src_size < offset + size)
		return;

	_copy(src);
}

io_ptr_interface::io_ptr_interface(const io_ptr_interface& src) :
	_io_mngr(0)
{
	_copy(src);
}

io_ptr_interface::~io_ptr_interface()
{
	empty();
}

void* io_ptr_interface::ptr() const
{
	return _io_ptr;
}

dword io_ptr_interface::offset() const
{
	return _io_offset;
}

uint32_t io_ptr_interface::size() const
{
	return _io_size;
}

void io_ptr_interface::empty()
{
	_detach(true);

	_io_ptr    = 0;
	_io_size   = 0;
	_io_offset = 0;
}

bool io_ptr_interface::is_empty() const
{
	return _io_ptr == 0;
}

bool io_ptr_interface::_is_attached() const
{
	return _io_mngr != 0;
}

io_manager* io_ptr_interface::_get_mngr() const
{
	return _io_mngr;
}

void io_ptr_interface::_attach(io_manager* mngr)
{
	if (_io_mngr != 0) 
		_io_mngr->_detach(this);
	
	_io_mngr = mngr;
	_io_mngr->_attach(this);
}

void io_ptr_interface::_detach(bool detach_mngr)
{
	if (_io_mngr != 0) {
		if (detach_mngr)
			_io_mngr->_detach(this);
	
		_io_mngr   = 0;
	}
}

void io_ptr_interface::_update(void* new_ptr)
{
	_io_ptr = new_ptr;
}

void io_ptr_interface::_copy(const io_ptr_interface& src)
{
	_detach(true);

	_io_ptr = src.ptr();
	_io_offset = src.offset();
	_io_size = src.size();

	if (src._is_attached()) {
		_io_mngr = src._get_mngr();
		_io_mngr->_attach(this);
	}
}

bool io_ptr_interface::_copy_range(io_ptr_interface& src, dword offset, uint32_t size)
{
	dword src_offset = src.offset();
	uint32_t src_size = src.size();

	if (size == 0 || src_offset > offset || src_offset + src_size < offset + size)
		return false;

	_detach(true);

	uint32_t diff = offset - src_offset;
	_io_ptr = reinterpret_cast<uint8_t*>(src.ptr()) + diff;
	_io_offset = offset;
	_io_size = size;

	if (src._is_attached()) {
		_io_mngr = src._get_mngr();
		_io_mngr->_attach(this);
	}

	return true;
}

// ======================= io_manager =======================

io_manager::io_manager()
{
}

io_manager::~io_manager()
{
	list<io_ptr_interface*>::iterator it = _io_ptrs.begin();
	while (it != _io_ptrs.end()) {
		(*it)->_detach(false);
		it++;
	}
}

void io_manager::update(void* ptr, dword offset, uint32_t size)
{
	dword peak = offset + size;
	list<io_ptr_interface*>::iterator it = _io_ptrs.begin();

	while (it != _io_ptrs.end()) {
		io_ptr_interface* ptr = *it;
		uint32_t old_offset = ptr->offset();
		uint32_t old_size = ptr->size();
		uint32_t old_peak = old_offset + old_size;

		if (old_offset >= offset && old_peak <= peak)
			ptr->_update((uint8_t*)ptr + old_offset - offset);

		it++;
	}
}

void io_manager::_attach(io_ptr_interface* ptr)
{
	_io_ptrs.push_back(ptr);
}

void io_manager::_detach(io_ptr_interface* ptr)
{
	list<io_ptr_interface*>::iterator it = _io_ptrs.begin();
	while (it != _io_ptrs.end()) {
		if (*it == ptr) {
			(*it)->_detach(false);
			_io_ptrs.erase(it);
			break;
		}
		it++;
	}
}

};//Monstra
