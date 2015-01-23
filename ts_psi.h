/*
 * ts_psih
 *
 *  Created on: 2015-1-18
 *      Author: shenwei
 */

#ifndef TS_PSI_H_
#define TS_PSI_H_

int32_t ts_psi_is_over(struct ts_packet *ts);

int32_t ts_psi_is_timeout(struct ts_packet *ts);

int32_t ts_psi_parse(struct ts_packet *ts, struct ts_pid *pid, char *buf, int size);

#endif /* TS_PAT_H_ */
