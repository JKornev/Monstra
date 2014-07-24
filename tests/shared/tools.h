#pragma once

#include <fstream>
#include <iostream>
#include <vector>

bool LoadRawBin(char* path, std::vector<char>& buf)
{
	std::fstream file(path, std::ios_base::in | std::ios_base::binary);

	if (!file) {
		return false;
	}

	buf.clear();

	file.seekg(0, std::ios_base::end);
	buf.insert(buf.begin(), static_cast<unsigned int>(file.tellg()), 0);
	file.seekg(0, std::ios_base::beg);
	file.read(&buf[0], buf.size());

	return true;
}