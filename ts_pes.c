/*
 * ts_pes.c
 *
 *  Created on: 2015-1-18
 *      Author: shenwei
 */

#include "ts_log.h"
#include "ts_buffer.h"
#include "ts_packet.h"
#include "ts_pid.h"


int32_t ts_pes_write_es( struct ts_pid *pid, char *buf, int32_t size){

	return size;
}

int32_t ts_pes_parse( struct ts_pid *pid){
	int32_t PES_packet_length ;
	int32_t PES_header_data_length;
	int32_t PTS_DTS_flags;
	char *p = pid->data_payload->data;
	int32_t size = ts_buffer_size(pid->data_payload);
	PES_packet_length = (p[4] << 8) | p[5];
	PTS_DTS_flags = (p[7] >> 6) & 0x03;
	PES_header_data_length = p[8];
	if(size < PES_header_data_length + 9){
		ts_warn("PES_header_data_length:%d too long than data size:%d\n", PES_packet_length, size);
		return 0;
	}
	if(PES_packet_length > 0 && PES_packet_length + PES_header_data_length + 9 > size){
		ts_warn("PES packet length:%d too long than data size:%d\n", PES_packet_length, size);
		return 0;
	}
	p = p + 9;
	if(PTS_DTS_flags == 2 && size >= 14){
		pid->pts = ((p[0] >> 1)&0x7) << 30;
		pid->pts |= (p[1]) << 22;
		pid->pts |= ((p[2] >> 1)&0x7F) << 15;
		pid->pts |= (p[3]) << 7;
		pid->pts |= ((p[4] >> 1)&0x7F) ;
	}else if(PTS_DTS_flags == 3 && size >= 19){
		pid->pts = ((p[0] >> 1)&0x7) << 30;
		pid->pts |= (p[1]) << 22;
		pid->pts |= ((p[2] >> 1)&0x7F) << 15;
		pid->pts |= (p[3]) << 7;
		pid->pts |= ((p[4] >> 1)&0x7F) ;

		p  = p + 5;
		pid->dts = ((p[0] >> 1)&0x7) << 30;
		pid->dts |= (p[1]) << 22;
		pid->dts |= ((p[2] >> 1)&0x7F) << 15;
		pid->dts |= (p[3]) << 7;
		pid->dts |= ((p[4] >> 1)&0x7F) ;
	}else{
		ts_warn("PES packet length:%d error\n",  size);
		return 0;
	}

	p = pid->data_payload->data + 9 + PES_header_data_length;
	if(PES_packet_length > 0){
		ts_pes_write_es( pid, p, PES_packet_length);
	}else{
		ts_pes_write_es( pid, p, size - (p - pid->data_payload->data));
	}
	return 0;
}




int32_t ts_pes_payload(struct ts_pid *pid, char *buf, int32_t off_size, int32_t size){
	int32_t payload_unit_start_indicator = (buf[1]>>6) & 0x1;
	int32_t adaptation_field_control = (buf[3] >> 4) & 0x3;
	char *p;
	int32_t stream_type;
	if(payload_unit_start_indicator){
		if(ts_buffer_size(pid->data_payload) >= 9){
			ts_pes_parse(  pid);
		}

		ts_buffer_init(pid->data_payload);
		pid->data_start = 1;
		pid->data_done = 0;
		pid->data_filter = 0;
		ts_buffer_write(pid->data_payload, buf + off_size, size - off_size);
	}else if(pid->data_start){
		ts_buffer_write(pid->data_payload, buf + off_size, size - off_size);
	}
	if(!pid->data_filter && ts_buffer_size(pid->data_payload) > 3){
		p = pid->data_payload->data;
		pid->data_filter = 1;
		/*packet_start_code_prefix: 00 00 01*/
		if(p[0] != 0 || p[1] != 0 || p[2] != 1){
			pid->data_filter = 0;
		}
		stream_type = p[3];
		if((stream_type & 0xf0) != 0xe0 || (stream_type & 0xe0) != 0xc0 ){
			pid->data_filter = 0;
		}
		if(pid->data_filter == 0){
			pid->data_start = 0;
			pid->data_done = 0;
			pid->data_filter = 0;
			ts_buffer_init(pid->data_payload);
		}
	}
	return 1;
}

int32_t ts_pes_collect(struct ts_pid *pid, char *buf, int32_t size){
		int32_t left_size = 0;
		int32_t adaptation_field_control = (buf[3] >> 4) & 0x3;

		if(adaptation_field_control == 1){
			ts_pes_payload(pid, buf,  4,  188);
		}else if(adaptation_field_control == 2){
			ts_field(pid, buf, 188);
		}else if(adaptation_field_control == 3){
			left_size = ts_field(pid, buf, 188);
			if(left_size > 0){
				ts_pes_payload(pid, buf,  184 - left_size,  188);
			}
		}
		return 1;
}


