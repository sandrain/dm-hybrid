/*
 * hystor_lib.c
 *
 * Author(s): Hyogi Sim <sandrain@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "hystor.h"
#include "hash_table.h"

/*
 * in-memory block table implementation
 */

/*
 * external interfaces
 */

int hystor_init(void)
{
	return 0;
}

int hystor_update_block_table(struct blk_io_trace *bit)
{
	if (!bit)
		return -1;

	return 0;
}

int hystor_request_remap(hy_block_t *list, int size)
{
	if (!list || !size)
		return 0;

	return size;
}

