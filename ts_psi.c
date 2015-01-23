/*
 * ts_pat.c
 *
 *  Created on: 2015-1-18
 *      Author: shenwei
 */

#include "ts_log.h"
#include "ts_buffer.h"
#include "ts_packet.h"
#include "ts_pid.h"


int32_t ts_payload(struct ts_packet *ts, struct ts_pid *pid, char *buf, int32_t offset){

	int32_t left_size = 0;
	int32_t payload_unit_start_indicator = (buf[1]>>6)& 0x1;

	left_size = 188 - offset;
	if(payload_unit_start_indicator){
		/*this psi/pes start  is the prev one end*/
		if(ts_buffer_size(pid->data_payload) > 3){
			pid->data_done = 1;
			pid->data_start = 0;
			switch(pid->type){
			case TS_VIDEO_PID:
			case TS_AUDIO_PID:
				break;
			case TS_PAT_PID:
				ts_pat_parse(ts, pid);
				if(pid->data_done){
					return 0;
				}
				break;
			case TS_PMT_PID:
				ts_pmt_parse(ts, pid);
				if(pid->data_done){
					return 0;
				}
				break;
			}
		}
		pid->data_done = 0;
		pid->data_start = 1;
		ts_buffer_init(pid->data_payload);
		ts_buffer_write(pid->data_payload, buf + offset, left_size);
	}else if(pid->data_start){
		ts_buffer_write(pid->data_payload, buf + offset, left_size);
	}
	return 0;
}

int32_t ts_data(struct ts_pid *pid, char *buf){
	int32_t left_size = 0;
	int32_t adaptation_field_control = (buf[3] >> 4) & 0x3;

	if(adaptation_field_control == 1){
		ts_payload(pid, buf,  4,  188);
	}else if(adaptation_field_control == 2){
		ts_field(pid, buf, 188);
	}else if(adaptation_field_control == 3){
		left_size = ts_field(pid, buf, 188);
		if(left_size > 0){
			ts_payload(pid, buf,  184 - left_size,  188);
		}
	}
	return 1;
}


int32_t ts_psi_collect(struct ts_pid *pid, char *buf){
	int32_t left_size = 0;
	int32_t payload_unit_start_indicator = (buf[1]>>6)& 0x1;
	left_size = ts_field(pid, buf, 188);
	if(!pid->field_done){
		return 1;
	}
	if(payload_unit_start_indicator){
		/*this psi start  is the prev one  end*/
		if(ts_buffer_size(pid->data_payload) > 3){
			pid->data_done = 1;
			pid->data_start = 0;
			return 1;
		}
		pid->data_done = 0;
		pid->data_start = 1;
		ts_buffer_init(pid->data_payload);
		ts_buffer_write(pid->data_payload, buf + 188 - left_size, left_size);
	}else if(pid->data_start){
		ts_buffer_write(pid->data_payload, buf + 4, 184);
	}
	return 0;
}

int32_t ts_pat_parse(struct ts_packet *ts, struct ts_pid *pid){
	int32_t i;
	char *p;
	int32_t size = ts_buffer_size(pid->data_payload);
	p = pid->data_payload->data;
	if(size <= 8){
		pid->data_done = 0;
		return 0;
	}
	int32_t table_id = p[0];
	if(table_id != 0x0){
		pid->data_done = 0;
		ts_warn("PAT table id:%d != 0x0\n", table_id);
		return 0;
	}
	int32_t section_length = ((p[1]&0xF) << 8) | p[2];
	if(section_length > size - 3){
		pid->data_done = 0;
		return 0;
	}
	ts->program_num = (section_length - 4 - 5)/4;
	ts->programs = ts_malloc(sizeof(struct ts_pmt)*ts->program_num);
	if(!ts->programs){
		ts_warn("malloc failed\n");
		return 0;
	}
	memset(ts->programs, 0 , sizeof(struct ts_pmt)*ts->program_num);

	p = p + 8;
	for(i = 0; i < ts->program_num; i++){
		ts->programs[i].service_id = (p[0] << 8) | p[1];
		ts->programs[i].pid = ((p[2]&0x1F) << 8) | p[3];
		p = p + 4;
	}

	ts->pat_done = 1;
	/*FIXME: no check crc*/

	return 1;
}

int32_t ts_add_pmt(struct ts_packet *ts, struct ts_pid *pat){
	assert(ts && pat && pat->type == TS_PAT_PID);
	int32_t i;
	int32_t pid;
	for(i = 0; i < ts->program_num; i++){
		pid = ts->programs[i].pid;
		ts->pids[pid] = ts_pid_new();
		if(!ts->pids[pid]){
			return 0;
		}
		ts_pid_init(ts->pids[pid], pid, TS_PMT_PID);
		ts->pids[pid]->service_id = ts->programs[i].service_id;
	}
	return 1;
}

struct es_info_header *ts_es_info_header_new(){
	struct es_info_header *es = ts_malloc(sizeof(*es));
	if(!es){
		ts_warn("malloc failed\n");
		return NULL;
	}
	memset(es, 0, sizeof(*es));
	return es;
}

void ts_es_info_header_free(struct es_info_header *es){
	if(es){
		ts_free(es);
	}
}

int32_t ts_add_es_info(struct ts_packet *ts, int32_t service_id, int32_t stream_type, int32_t pid){

	struct es_info_header *es = ts_es_info_header_new();
	if(!es){
		return 0;
	}
	int32_t i;
	struct ts_pmt *program = NULL;
	for(i = 0; i < ts->program_num; i++){
		if(ts->programs[i].service_id == service_id){
			program = &ts->programs[i];
			break;
		}
	}
	if(program){
		es->next = program->next;
		program->next = es;
	}else{
		ts_es_info_header_free(es);
		ts_warn("No find service id:%d in programs table\n", service_id);
		return 0;
	}
	return 1;
}

int32_t ts_pmt_done(struct ts_packet *ts, int32_t service_id){
	int32_t i;
	int32_t find = 0;
	int32_t all_done = 1;
	for(i = 0; i < ts->program_num; i++){
		if(ts->programs[i].service_id == service_id){
			ts->programs[i].over = 1;
			find = 1;
		}
		/*exclude service id:0 that pid is ts id*/
		if(!ts->programs[i].over && ts->programs[i].service_id != 0){
			all_done = 0;
		}
	}
	if(all_done){
		ts->pmts_done = 1;
	}
	return 1;
}

int32_t ts_pmt_parse(struct ts_packet *ts, struct ts_pid *pid){
	int32_t i;
	int32_t service_id;
	char *p;
	int32_t size = ts_buffer_size(pid->data_payload);
	p = pid->data_payload->data;
	if(size <= 12){
		pid->data_done = 0;
		return 0;
	}
	int32_t table_id = p[0];
	if(table_id != 0x02){
		pid->data_done = 0;
		ts_warn("PMT table id:%d != 0x02\n", table_id);
		return 0;
	}
	int32_t section_length = ((p[1]&0xF) << 8) | p[2];
	if(section_length > size - 3){
		pid->data_done = 0;
		return 0;
	}
	int program_info_length;
	/*CRC:4 bytes,section head:9 bytes*/
	if(section_length - 4 - 9 > 0){
		program_info_length = p[12];
	}else{
		return 0;
	}
	if(section_length - 4 - 9 - program_info_length <= 0){
		ts_warn("PMT no elementary_PID\n");
		return 0;
	}
	char *end = p + section_length - 3 - 4;
	p = p + 12 + program_info_length;
	int32_t ES_info_length;
	int32_t stream_type;
	int32_t elementary_PID;
	while(p < end){
		stream_type = p[0];
		elementary_PID = ((p[1]&0x1F)<< 8)|p[2];
		ES_info_length = ((p[3]&0xF)<< 8)|p[4];
		ts_add_es_info(ts,  service_id,  stream_type,  elementary_PID);
		p = p + 3 + ES_info_length;
	}

	ts_pmt_done(ts, service_id);
	/*FIXME: no check crc*/

	return 1;
}

int32_t ts_add_elementary_PID(struct ts_packet *ts){
	int32_t i;
	int32_t pid;
	struct es_info_header *es;
	for(i = 0; i < ts->program_num; i++){
		if(ts->programs[i].service_id == 0){
			continue;
		}
		es = ts->programs[i].next;
		while(es){
			pid = ts->programs[i].pid;
			ts->pids[pid] = ts_pid_new();
			if(!ts->pids[pid]){
				return 0;
			}
			ts_pid_init(ts->pids[pid], pid, TS_PMT_PID);
			ts->pids[pid]->service_id = ts->programs[i].service_id;
			es = es->next;
		}
	}
	return 1;
}

int32_t ts_psi_is_done(struct ts_packet *ts){
	return ts->pmts_done;
}



int32_t ts_psi_parse(struct ts_packet *ts, struct ts_pid *pid, char *buf, int size){

	ts_psi_collect(pid, buf, size);
	if(pid->data_done){
		if(pid->type == TS_PAT_PID){
			ts_pat_parse(ts, pid);
		}else if(pid->type == TS_PMT_PID){
			ts_pmt_parse(ts, pid);
		}
	}
	return 1;
}

int32_t ts_psi_is_timeout(struct ts_packet *ts){
	struct timeval now;
	gettimeofday(&now, NULL);
	return (now.tv_sec > ts->psi_start_tv.tv_sec + ts->psi_parse_timeout);
}
