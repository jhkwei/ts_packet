/*
 * ts_buffer.c
 *
 *  Created on: 2015-1-18
 *      Author: shenwei
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ts_log.h"
#include "ts_buffer.h"



static int32_t ts_buffer_resize(struct ts_buffer *b, int32_t size){
	if(size <= 0){
		ts_warn();
		return 0;
	}
	int length = b->length;
	while(length < size){
		length = length * 2;
	}
	char *data = ts_malloc(length);
	if(!data){
		ts_warn("malloc failed\n");
		return 0;
	}

	int curr = b->curr - b->data;
	memcpy(data, b->data, curr);
	ts_free(b->data);
	b->data = data;
	b->curr = b->data + curr;
	b->length = length;

	return size;
}

struct ts_buffer *ts_buffer_new(){

	struct ts_buffer *b;
	b = ts_malloc(sizeof(*b));
	if(!b){
		ts_warn("malloc failed\n");
		return NULL;
	}
	memset(b, 0, sizeof(*b));
	if(!ts_buffer_resize(b, 1024)){
		ts_free(b);
		return NULL;
	}
	return b;
}


void ts_buffer_free(struct ts_buffer *b){
	assert(b);
	if(b->data){
		ts_free(b->data);
	}
	ts_free(b);

}

void ts_buffer_init(struct ts_buffer *b){
	assert(b);
	b->curr = b->data;
}

int32_t ts_buffer_size(struct ts_buffer *b){
	assert(b);
	return b->curr - b->data;
}

int32_t ts_buffer_write(struct ts_buffer *b, char *data, int32_t size){
	assert(b && data && size > 0);
	if(b->curr - b->data + size > b->length){
		if(!ts_buffer_resize(b, b->curr - b->data + size)){
			ts_warn("buffer resize form:%d to:%d failed!\n", ts_buffer_size(), ts_buffer_size() + size);
			return 0;
		}
	}
	memcpy(b->curr, data, size);
	b->curr = b->curr + size;
	return size;
}

int32_t ts_buffer_read(struct ts_buffer *b, char *data, int32_t size){
	assert(b && data && size > 0);
	if( b->curr - b->data < size){
		ts_warn("require data size:%d > buffer data size:%d\n", size, ts_buffer_size(b));
		return 0;
	}
	memcpy(data, b->data, size);
	return size;
}



