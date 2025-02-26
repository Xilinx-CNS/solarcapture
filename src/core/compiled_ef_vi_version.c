/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * Just a simple helper used to obtain the version of ef_vi that is installed
 * intended to be run during build, so that we can compare against it later.
 */

#include <stdio.h>
#include <etherfabric/vi.h>

int main(void) {
	int rc;

	printf("#define COMPILED_EF_VI_VERSION \"%s\"\n", ef_vi_version_str());

	return rc < 0 ? errno : 0;
}
