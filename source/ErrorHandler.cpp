#include "ErrorHandler.h"
#include <string.h>
#include <sstream>


using namespace std;

namespace Monstra {

ErrorCtrl::ErrorCtrl()
{ 
	ClearError();
}

ErrorCtrl::~ErrorCtrl()
{
}

ErrorCtrl::ErrorCtrl(const ErrorCtrl &src)
{
	CopyError(src);
}

bool ErrorCtrl::SetErrorA(unsigned int error, unsigned int sub, char* descr)
{
	if (error != E_INHERIT) {
		_error = error;
		_sub = sub;
		_descr = (descr != 0 ? descr : "");
	} else {
		//E_INHERIT must be used only with errors
	}
	return (_error == E_OK ? true : false);
}

bool ErrorCtrl::SetErrorA(unsigned int error, unsigned int sub, string &descr)
{
	if (error != E_INHERIT) {
		_error = error;
		_sub = sub;
		_descr = descr;
	} else {
		//E_INHERIT must be used only with errors
	}
	return (_error == E_OK ? true : false);
}

void ErrorCtrl::ClearError()
{
	_error = E_OK;
	_sub = 0;
	_descr = "";
}


bool ErrorCtrl::CopyError(const ErrorCtrl &src)
{
	_error = src._error;
	_sub = src._sub;
	_descr = src._descr;
	return (_error == E_OK ? true : false);
}

void ErrorCtrl::GetError(unsigned int &error, unsigned int &sub, string &descr)
{
	error = _error;
	sub = _sub;
	descr = _descr;
}

void ErrorCtrl::GetFormattedError(std::string &str)
{
	std::stringstream str_stream;
	str_stream << "error: " << _error << " (" << GetErrorCodeDescrStr(_error) 
		<< "), code: " << _sub << ", descr: \"" << (_descr.empty() ? "none" : _descr) << "\"";
	str = str_stream.str();
}

const char *ErrorCtrl::GetErrorCodeDescrStr(unsigned int code)
{
	const char *str = "unknown";
	switch (code) {
	case E_OK:
		str = "no error";
		break;
	case E_NOT_FOUND:
		str = "not found";
		break;
	case E_FOUND:
		str = "founded";
		break;
	case E_ALREADY:
		str = "already";
		break;
	case E_OVERFLOW:
		str = "overflow";
		break;
	case E_OUT_OF_RANGE:
		str = "out of range";
		break;
	case E_ACCESS_DENIED:
		str = "access denied";
		break;
	case E_ALLOC_FAIL:
		str = "allocation failed";
		break;
	case E_NOT_SUPPORTED:
		str = "not supported";
		break;
	case E_NOT_ENOUGH:
		str = "not enough";
		break;
	case E_INVALID_PARAMS:
		str = "invalid params";
		break;
	case E_SYSTEM:
		str = "system error";
		break;
	default:
		break;
	}
	return str;
}

};/*Monstra namespace*/