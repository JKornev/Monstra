#ifndef _MONSTRA_IO_POINTER_H
#define _MONSTRA_IO_POINTER_H

#include "BaseDefs.h"
#include <list>

namespace Monstra {

class io_manager;

class io_ptr_interface {
public:
	io_ptr_interface(io_manager* mngr = 0, void* ptr = 0, dword offset = 0, uint32_t size = 0);
	io_ptr_interface(const io_ptr_interface& src, dword offset, uint32_t count);
	io_ptr_interface(const io_ptr_interface& src);
	~io_ptr_interface();

	void* ptr() const;
	dword offset() const;
	uint32_t size() const;
	bool is_empty() const;
	void empty();

protected:
	io_manager* _io_mngr;
	void*       _io_ptr;
	dword       _io_offset;
	uint32_t    _io_size;

protected:
	void _attach(io_manager* mngr);
	void _detach(bool detach_mngr);
	void _update(void* new_ptr);
	void _copy(const io_ptr_interface& src);
	bool _copy_range(io_ptr_interface& src, dword offset, uint32_t size);

	bool _is_attached() const;
	io_manager* _get_mngr() const;

	friend io_manager;
};

template<typename T>
class io_ptr : public io_ptr_interface {
public:
	io_ptr() { }
	io_ptr(io_manager* mngr, void* buf, dword offset, uint32_t count) : io_ptr_interface(mngr, buf, offset, sizeof(T) * count) { }
	io_ptr(void* buf, dword offset, uint32_t count) : io_ptr_interface(0, buf, offset, sizeof(T) * count) { }
	io_ptr(const io_ptr& src) : io_ptr_interface(src) { }
	io_ptr(const io_ptr& src, dword offset, uint32_t count) : io_ptr_interface(src, offset, count * sizeof(T)) { }

	T* ptr()
	{
		return reinterpret_cast<T*>(_io_ptr);
	}

	const T* ptr() const
	{
		return reinterpret_cast<T*>(_io_ptr);
	}

	uint32_t count() const
	{
		return _io_size / sizeof(T);
	}

	bool copy_range(io_ptr_interface& src, dword offset, uint32_t count = 1)
	{
		return _copy_range(src, offset, sizeof(T) * count);
	}

	T* operator-> ()
	{
		if (is_empty())
			throw std::exception("io_ptr: bad ptr");
		
		return reinterpret_cast<T*>(_io_ptr);
	}

	T* operator-> () const
	{
		if (is_empty())
			throw std::exception("io_ptr: bad ptr");
		
		return reinterpret_cast<T*>(_io_ptr);
	}

	T& operator[] (uint32_t inx)
	{
		if (is_empty())
			throw std::exception("io_ptr: bad ptr");
		
		if (sizeof(T) * (inx + 1) > size())
			throw std::exception("io_ptr: out of range");
		
		return *reinterpret_cast<T*>(ptr() + inx);
	}

	const T& operator[] (uint32_t inx) const
	{
		if (is_empty())
			throw std::exception("io_ptr: bad ptr");
		
		if (sizeof(T) * (inx + 1) > size())
			throw std::exception("io_ptr: out of range");
		
		return *reinterpret_cast<const T*>(ptr() + inx);
	}

	io_ptr& operator= (const io_ptr& src)
	{
		_copy(src);
		return *this;
	}

protected:
};

class io_manager {
public:
	io_manager();
	~io_manager();

	void update(void* ptr, dword offset, uint32_t size);

private:
	std::list<io_ptr_interface*> _io_ptrs;

private:
	void _attach(io_ptr_interface* ptr);
	void _detach(io_ptr_interface* ptr);

	friend io_ptr_interface;
};

};//Monstra


#endif
