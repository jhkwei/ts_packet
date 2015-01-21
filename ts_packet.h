/*
 * ts_packet.h
 *
 *  Created on: 2015-1-18
 *      Author: shenwei
 */

#ifndef TS_PACKET_H_
#define TS_PACKET_H_

enum ts_pid_type{
	TS_UNKNOWN_PID,
	TS_PAT_PID,
	TS_PMT_PID,
	TS_STD_PID,
	TS_NIT_PID,
	TS_EIT_PID,
	TS_PCR_PID,
	TS_VIDEO_PID,
	TS_AUDIO_PID,
	TS_PID_TYPE_NUM
};


struct es_info_header{
	int32_t stream_type;
	int32_t pid;
	struct es_info_header *next;
};


struct ts_pid{
	int32_t pass;
	int32_t pid;
	int32_t service_id;/*the pid in service id when pid type is AUDIO or VIDEO*/
	int32_t type;
	int64_t pts;
	int64_t dts;

	int32_t continuity_counter;

	// adaptation field or point field
	int32_t field_done;
	int32_t field_start;
	int32_t field_length;
	int32_t field_current_length;

	int32_t data_done;
	int32_t data_start;
	int32_t data_length;
	int32_t data_crrent_length;
	int32_t data_filter;

	struct ts_buffer *adaptation_field;
	struct ts_buffer *data_payload;

	void *priv_data;
};

struct ts_pmt{
	int32_t pass;
	int32_t service_id; /*program_number*/
	int32_t pid;  /*pid == 0, ts id ; pid > 0, pmt pid*/
	int32_t over; /*pmt pid parse over*/
	char *service_name;
	int32_t es_info_num;
	struct es_info_header *next;
	void *priv_data;
};

struct ts_packet{
	int32_t pat_done;
	int32_t pmts_done;
	int32_t ts_id;		/*stream id*/
	int32_t output_enable;

	int32_t psi_parse_timeout;
	struct timeval psi_start_tv;

	struct ts_pid *pids[8192];
	int32_t program_num;
	struct ts_pmt *programs;

	int32_t filter_pid_num;
	int32_t *filter_pids;

	int32_t filter_service_id_num;
	int32_t *filter_service_ids;


	void *priv_data;

};

struct ts_packet *ts_packet_init();

void ts_packet_exit(struct ts_packet *ts);

int32_t ts_packet(struct ts_packet *ts, char *buf,  int32_t size,  int32_t ts_len);

int32_t ts_es_output( struct ts_packet *ts,struct ts_pid *pid, char *buf, int32_t size);

int32_t ts_set_pid_filter_table(struct ts_packet *ts, int32_t pids[], int32_t size);

int32_t ts_set_service_id_filter_table(struct ts_packet *ts, int32_t service_ids[], int32_t size);

void ts_output_config(struct  ts_packet *ts);

#endif /* TS_PACKET_H_ */
