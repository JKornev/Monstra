#ifndef __MONSTRA_PE_SECTIONS_H
#define __MONSTRA_PE_SECTIONS_H

#include "PEDefs.h"
#include "PEParser.h"
#include "PEHeader.h"
#include "ErrorHandler.h"

#include <vector>

namespace Monstra {

// Parser
// Parser is implemented in PEHeaderParser

// Container

class PESections : public std::vector<PEImgSectionHeader> {
public:
	PESections();
	~PESections();

	bool Load(PEHeaderParser& parser);
	void Clear();
};

// Builder

class PESectionsBuilder : public MONSTRA_ERROR_CTRL {
public:
	PESectionsBuilder();
	~PESectionsBuilder();

private:

};

};/*Monstra namespace*/

#endif
