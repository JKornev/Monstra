#ifndef __MONSTRA_ERROR_HANDLER_H
#define __MONSTRA_ERROR_HANDLER_H

#include <string>

//=======================================
//TODO реализовать соответствие с cmake конфигурациями
#define MONSTRA_ENABLE_ERROR_CTRL
#define MONSTRA_ENABLE_ERROR_DESCR
//=======================================

#if defined(MONSTRA_ENABLE_ERROR_CTRL)

# define MONSTRA_ERROR_CTRL ErrorCtrl

# if defined(MONSTRA_ENABLE_ERROR_DESCR)
#  define SetError SetErrorA
# else
#  define SetError(code, sub, descr) SetErrorA(code, sub, 0)
# endif

# define SetErrorOK       SetError(E_OK, 0, NULL)
# define SetErrorInherit  SetError(E_INHERIT, 0, NULL)
# define InheritErrorFrom CopyError
// Notice: macro SetError() and InheritErrorFrom() must be used only with errors
 

#else

# define MONSTRA_ERROR_CTRL ErrorCtrlStub
# define SetError(code, sub, descr) false
# define SetErrorOK true
# define SetErrorInherit false
# define InheritErrorFrom false

#endif

//=======================================

namespace Monstra {

enum DefErrorCode {
	//ok
	E_OK,
	//inherit last error
	E_INHERIT,
	//errors
	E_UNKNOWN,
	E_NOT_FOUND,
	E_FOUND,
	E_ALREADY,
	E_OVERFLOW,
	E_OUT_OF_RANGE,
	E_ACCESS_DENIED,
	E_ALLOC_FAIL,
	E_NOT_SUPPORTED,
	E_NOT_ENOUGH,
	E_INVALID_PARAMS,
	E_SYSTEM,
};

class ErrorCtrl {
	std::string _descr;
	unsigned int _error;
	unsigned int _sub;

	static const char* GetErrorCodeDescrStr(unsigned int code);
public:

	ErrorCtrl();
	ErrorCtrl(const ErrorCtrl &src);
	~ErrorCtrl();

	bool SetErrorA(unsigned int error, unsigned int sub, char* descr);
	bool SetErrorA(unsigned int error, unsigned int sub, std::string& descr);
	void ClearError();

	bool CopyError(const ErrorCtrl& src);

	void GetError(unsigned int& error, unsigned int& sub, std::string& descr);
	void GetFormattedError(std::string& str);
};

class ErrorCtrlStub { };

};/*Monstra namespace*/

#endif
