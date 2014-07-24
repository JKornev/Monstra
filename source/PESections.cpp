#include "PESections.h"

using namespace std;

namespace Monstra {

// ======================= PESections =======================

PESections::PESections()
{
}

PESections::~PESections()
{
}

bool PESections::Load(PEHeaderParser& parser)
{
	Clear();

	if (!parser.IsParsed()) {
		return false;
	}

	PEImgSectionHeader_ptr psect = parser.GetSectors();
	if (psect.is_empty()) {
		return true;
	}

	for (uint32_t i = 0, count = psect.count(); i < count; i++) {
		push_back(psect[i]);
	}

	return true;
}

void PESections::Clear()
{
	clear();
}

// ======================= PESectionsBuilder =======================

};//Monstra
