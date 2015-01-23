/*
 * ts_field.c
 *
 *  Created on: 2015-1-18
 *      Author: shenwei
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "ts_log.h"
#include "ts_buffer.h"
#include "ts_packet.h"
#include "ts_pid.h"


/*just jump adaptation or point field*/
int32_t ts_field(struct ts_pid *pid, char *buf, int32_t size){
	assert(pid && buf && size > 0);
	int32_t left_size = 0;
	int32_t field_control = (buf[3]>>4)&0x3;
	int32_t payload_unit_start_indicator = (buf[1]>>6)&0x1;
	if(payload_unit_start_indicator){
		pid->field_done = 0;
		pid->field_length = buf[4];
		//ts_buffer_init(pid->field);
		if(size - 5 <= pid->field_length){
			ts_warn("field length:%d error\n", pid->field_length);
			pid->field_done = 0;
		}else{
			//ts_buffer_write(pid->field, buf + 5, size - 5);
			left_size = size - 5 - pid->field_length;
			pid->field_done = 1;
		}
	}
	return left_size;
}
