#include <fvad.h>
#include <switch.h>
#include <sys/time.h>
// #include "rnnoise.h"

#define VAD_PRIVATE "_vad_"		  // vad模块哈希key值
#define VAD_XML_CONFIG "vad.conf" // 配置文件名
// #define VAD_EVENT_SUBCLASS "vad::detection" //vad自定义事件名
#define PORT 8001		 // 目标地址端口号
#define ADDR "127.0.0.1" // 目标地址IP

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_vad_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_vad_load);
SWITCH_MODULE_DEFINITION(mod_vad, mod_vad_load, mod_vad_shutdown, NULL);
SWITCH_STANDARD_APP(vad_start_function);

/*typedef enum {
	SWITCH_VAD_STATE_NONE,
	SWITCH_VAD_STATE_START_TALKING,
	SWITCH_VAD_STATE_TALKING,
	SWITCH_VAD_STATE_STOP_TALKING,
	SWITCH_VAD_STATE_ERROR
} switch_vad_state_t;*/

typedef struct {
	switch_core_session_t *session;
	switch_codec_implementation_t *read_impl;
	switch_media_bug_t *read_bug;
	switch_memory_pool_t *pool;
	int stop_talk_to_recognition_time;
	int no_sound_timeout;
	int talking;
	int divisor;
	int thresh;
	int channels;
	int sample_rate;
	int read_fd;
	int write_fd;
	int cfd;
	int fileflag;
	int callend_play;
	int pthread_exit;
	char AudioDir[128];
	char recv_path[128];
	char call_flag[16];
	switch_bool_t cond_flag;
	switch_bool_t is_playback_end;
	switch_bool_t log_flag;
	struct timeval tv_talking, tv_stop_talking;
	char *uuid;
	Fvad *fvad;
	switch_vad_state_t vad_state;
	// DenoiseState *st;
	switch_mutex_t *mutex;
	switch_thread_t *thread;
	switch_thread_cond_t *cond;
} switch_vad_docker_t;

static struct {
	int mode;
	int no_sound_timeout;
	int stop_talk_to_recognition_time;
	int isSync;
} globals;

static char *vad_serialize_json(switch_vad_docker_t *vad, int callstatus)
{
	cJSON *pJson = NULL;
	char *writebuf = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(vad->session);
	const char *nlp_type = switch_channel_get_variable(channel, "nlp_type");
	if (nlp_type == NULL) {
		nlp_type = "huoli_model";
		// 变量不存在
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "nlp_type变量不存在 !! : %s \n",nlp_type);
	} else {
		// 变量存在并且有值
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "nlp_type变量存在 !! : %s \n",nlp_type);
	}
	pJson = cJSON_CreateObject();
	if (NULL == pJson) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "cJSON_CreateObject Failed !!\n");
		return NULL;
	}

	if (callstatus == 1) {
		cJSON_AddStringToObject(pJson, "flag", "call_start");
	} else {
		cJSON_AddStringToObject(pJson, "flag", "call_end");
	}

	cJSON_AddStringToObject(pJson, "uuid", vad->uuid);
	if (strlen(nlp_type) == 0) {
		nlp_type = "gpt";
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "nlp_type is %s!!\n", nlp_type);
	}

	cJSON_AddStringToObject(pJson, "nlp_type", nlp_type);
	cJSON_AddStringToObject(pJson, "audio_file_path", vad->AudioDir);
	if (globals.isSync == 1) {
		cJSON_AddStringToObject(pJson, "asr_type", "stream");
	} else if (globals.isSync == 2) {
		cJSON_AddStringToObject(pJson, "asr_type", "file");
	}

	writebuf = cJSON_PrintUnformatted(pJson);
	if (NULL == writebuf) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "cJSON_Print is null!!\n");
		cJSON_Delete(pJson);
		return NULL;
	}

	cJSON_Delete(pJson);

	return writebuf;
}

static char *vad_parse_Json(char *readbuf, switch_vad_docker_t *vad)
{
	cJSON *pJson = NULL;
	cJSON *pSub = NULL;
	cJSON *pSub_Flag = NULL;
	char *path = NULL;
	char *flag = NULL;

	if (NULL == readbuf) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "readbuf is null!!\n");
		return NULL;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "readbuf is %s\n", readbuf);
	pJson = cJSON_Parse(readbuf);
	if (NULL == pJson) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Create cJSON fail!!\n");
		return NULL;
	}

	pSub = cJSON_GetObjectItem(pJson, "tts_file_path");
	if (NULL == pSub) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Get tts_file_path fail!!\n");
		return NULL;
	} else {
		path = pSub->valuestring;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Get tts_file_path is %s\n", path);
		memset(vad->recv_path, 0, sizeof(vad->recv_path));
		memcpy(vad->recv_path, path, strlen(path));
	}

	pSub_Flag = cJSON_GetObjectItem(pJson, "flag");
	if (pSub_Flag != NULL) {
		flag = pSub_Flag->valuestring;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Get flag is %s\n", flag);

		if (0 == (strcmp(flag, "call_end")) || 0 == (strcmp(flag, "tts_end"))) {
			memset(vad->call_flag, 0, sizeof(vad->call_flag));
			memcpy(vad->call_flag, flag, strlen(flag));
			cJSON_Delete(pJson);
			return vad->call_flag;
		}
	} else if (NULL == pSub_Flag) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Get audio_file_path fail!!\n");
		return NULL;
	}

	cJSON_Delete(pJson);
	return vad->recv_path;
}

static int create_client(switch_vad_docker_t *g_vad)
{
	struct sockaddr_in SockAddr = {0};
	int ret = -1;

	g_vad->cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_vad->cfd < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to bind socket\n");
		return g_vad->cfd;
	}

	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = htons(PORT);
	inet_pton(AF_INET, ADDR, &SockAddr.sin_addr.s_addr);

	if (0 > (ret = connect(g_vad->cfd, (struct sockaddr *)&SockAddr, sizeof(SockAddr)))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, " errorno is %s  \n", strerror(errno));
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "connect server success!!! \n");
	}

	return ret;
}

/*SWITCH_DECLARE(const char *)
switch_vad_state2str(switch_vad_state_t state)
{
	switch (state) {
	case SWITCH_VAD_STATE_NONE:
		return "no sounds";
	case SWITCH_VAD_STATE_START_TALKING:
		return "start_talking";
	case SWITCH_VAD_STATE_TALKING:
		return "talking";
	case SWITCH_VAD_STATE_STOP_TALKING:
		return "stop_talking";
	default:
		return "error";
	}
}*/

static int load_config(void)
{
	switch_xml_t cfg, xml, settings, param;

	if (!(xml = switch_xml_open_cfg(VAD_XML_CONFIG, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to open XML configuration '%s'\n",
						  VAD_XML_CONFIG);
		return -1;
	}

	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *)switch_xml_attr_soft(param, "name");
			char *val = (char *)switch_xml_attr_soft(param, "value");
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Found parameter %s=%s\n", var, val);
			if (!strcasecmp(var, "mode")) {
				globals.mode = atoi(val);
			} else if (!strcasecmp(var, "no_sound_timeout")) {
				globals.no_sound_timeout = atoi(val);
			} else if (!strcasecmp(var, "stop_talk_to_recognition_time")) {
				globals.stop_talk_to_recognition_time = atoi(val);
			} else if (!strcasecmp(var, "sync")) {
				globals.isSync = atoi(val);
			}
			/*else if (!strcasecmp(var, "nlp_type"))
			{
				// globals.nlp_type = val;
				switch_set_string(globals.nlp_type, val);
			}*/
		}
	}

	switch_xml_free(xml);
	return 0;
}

static switch_bool_t switch_vad_docker_init(switch_vad_docker_t *vad)
{
	if (NULL == vad) return SWITCH_FALSE;

	vad->no_sound_timeout = globals.no_sound_timeout;
	vad->stop_talk_to_recognition_time = globals.stop_talk_to_recognition_time;
	vad->talking = 0;
	vad->divisor = vad->sample_rate / 8000;
	vad->thresh = 0;
	vad->vad_state = SWITCH_VAD_STATE_NONE;
	vad->read_fd = -1;
	vad->write_fd = -1;
	vad->cfd = -1;
	vad->fileflag = 0;
	vad->uuid = NULL;
	vad->cond_flag = FALSE;
	vad->is_playback_end = TRUE;
	vad->log_flag = TRUE;
	vad->callend_play = 0;
	vad->pthread_exit = 0;
	memset(vad->recv_path, 0, 128);

	if (globals.mode < 0) {
		if (vad->fvad) {
			fvad_free(vad->fvad);
			vad->fvad = NULL;
			return SWITCH_FALSE;
		}
	} else if (globals.mode > 3) {
		globals.mode = 3;
	}

	if (NULL == vad->fvad) {
		vad->fvad = fvad_new();
		if (NULL == vad->fvad) switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "libfvad init error\n");
	} else {
		fvad_reset(vad->fvad);
	}

	if (vad->fvad) {
		fvad_set_mode(vad->fvad, globals.mode);
		fvad_set_sample_rate(vad->fvad, vad->sample_rate);
	}

	return SWITCH_TRUE;
}

SWITCH_DECLARE(switch_vad_state_t)
switch_vad_docker_process(switch_vad_docker_t *vad, int16_t *data, unsigned int samples)
{
	int energy = 0, j = 0, count = 0;
	int score = 0;
	long time_diff = 0;

	if (vad->vad_state == SWITCH_VAD_STATE_STOP_TALKING) {
		vad->vad_state = SWITCH_VAD_STATE_NONE;
	} else if (vad->vad_state == SWITCH_VAD_STATE_START_TALKING) {
		vad->vad_state = SWITCH_VAD_STATE_TALKING;
	}

	if (vad->fvad) {
		int ret = fvad_process(vad->fvad, data, samples);
		if (ret == -1) { switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "invalid frame length \n"); }
		score = vad->thresh + ret - 1;
	} else {
		for (energy = 0, j = 0, count = 0; count < samples; count++) {
			energy += abs(data[j]);
			j += vad->channels;
		}

		score = (uint32_t)(energy / (samples / vad->divisor));
	}

	if (score < vad->thresh) {
		gettimeofday(&vad->tv_stop_talking, NULL);
	} else {
		vad->vad_state = vad->talking ? SWITCH_VAD_STATE_TALKING : SWITCH_VAD_STATE_START_TALKING;
		vad->talking = 1;
		gettimeofday(&vad->tv_talking, NULL);
	}

	time_diff = (((vad->tv_stop_talking.tv_sec * 1000) + (vad->tv_stop_talking.tv_usec / 1000)) -
				 ((vad->tv_talking.tv_sec * 1000) + (vad->tv_talking.tv_usec / 1000)));
	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "time_diff is %ld \n", time_diff);

	if (vad->vad_state != SWITCH_VAD_STATE_START_TALKING && vad->vad_state != SWITCH_VAD_STATE_NONE) {
		if ((vad->tv_stop_talking.tv_sec - vad->tv_talking.tv_sec) < vad->no_sound_timeout) {

			if (time_diff < vad->stop_talk_to_recognition_time) {
				vad->vad_state = SWITCH_VAD_STATE_TALKING;
			} else {
				vad->vad_state = SWITCH_VAD_STATE_STOP_TALKING;
				vad->talking = 0;
			}
		} else {
			vad->vad_state = SWITCH_VAD_STATE_NONE;
			vad->talking = 0;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "VAD state is :%s\n",
							  switch_vad_state2str(vad->vad_state));
		}
	} else {
		gettimeofday(&vad->tv_talking, NULL);
		gettimeofday(&vad->tv_stop_talking, NULL);
	}

	return vad->vad_state;
}

static void *SWITCH_THREAD_FUNC RecvAndPlayBackPthread(switch_thread_t *thread, void *user_data)
{
	switch_vad_docker_t *vad = (switch_vad_docker_t *)user_data;
	char readbuf[360] = {0};
	char sendbuf[320] = {0};
	char *parse_json = NULL;
	int ret = -1;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	switch_channel_t *channel = switch_core_session_get_channel(vad->session);

	strcpy(sendbuf, "playback_end");
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
					  "----------------RecvAndPlayBackPthread start !!----------------\n");

	while (switch_channel_media_ready(channel)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvAndPlayBackPthread phread while 1 %s!\n",vad->uuid);
		ret = recv(vad->cfd, readbuf, sizeof(readbuf), 0);
		if (ret < 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvAndPlayBackPthread: recv() fail errno: %s!!\n",
							  strerror(errno));
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			break;
		} else if (ret > 0) {
			parse_json = vad_parse_Json(readbuf, vad);
			if (NULL == parse_json) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvAndPlayBackPthread: parse_str is NULL!\n");
				break;
			} else if (0 == (strcmp(parse_json, "call_end"))) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "RecvAndPlayBackPthread: vad_parse_Json success call flag is call_end!!\n");

				if (vad->callend_play == 0) {
					status = switch_ivr_play_file(vad->session, NULL, vad->recv_path, NULL);
					if (status != SWITCH_STATUS_SUCCESS) {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
										  "RecvAndPlayBackPthread: switch_ivr_play_file fail!!\n");
						break;
					}
					//switch_assert(!(fh.flags & SWITCH_FILE_OPEN));
					vad->callend_play++;
					switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
				}

				break;
			} else if(0 == (strcmp(parse_json, "tts_end"))){
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "RecvAndPlayBackPthread: vad_parse_Json success ---- soundfile path is %s\n",
								  parse_json);
				vad->is_playback_end = FALSE;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "RecvAndPlayBackPthread: 开始播放音频文件 is_playback_end标志是 %d\n",
								  vad->is_playback_end);
				status = switch_ivr_play_file(vad->session, NULL, vad->recv_path, NULL);
				if (status != SWITCH_STATUS_SUCCESS) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
									  "RecvAndPlayBackPthread: switch_ivr_play_file fail!!\n");
					break;
				}
				//switch_assert(!(fh.flags & SWITCH_FILE_OPEN));
				if (!switch_channel_media_ready(channel)) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
									  "RecvAndPlayBackPthread: channel not ready! \n");
					break;
				}
				
				vad->cond_flag = TRUE;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "RecvAndPlayBackPthread: vad->cond_flag set true \n");
				switch_sleep(20 * 1000);

				while (switch_channel_media_ready(channel)) {
                    //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvAndPlayBackPthread phread while 2 %s!\n",vad->uuid);
					if (vad->cond_flag == FALSE) {
						switch_mutex_lock(vad->mutex);

						ret = send(vad->cfd, sendbuf, 320, 0);
						if (ret < 0) {
							switch_log_printf(
								SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
								"RecvAndPlayBackPthread: when stop send socket data fail errno is :%s!!\n",
								strerror(errno));
							switch_thread_cond_broadcast(vad->cond);
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
											  " RecvAndPlayBackPthread: -------- 失败时的signal信号已经发送!!\n");
							switch_mutex_unlock(vad->mutex);
							switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
							break;
						} else if (ret > 0) {
							switch_thread_cond_broadcast(vad->cond);
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, " -------- signal信号已经发送!!\n");

							switch_mutex_unlock(vad->mutex);
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, " -------- 子线程解锁 !!\n");
							vad->is_playback_end = TRUE;
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "RecvAndPlayBackPthread: 音频文件播放完毕 is_playback_end标志是 %d\n",
								  vad->is_playback_end);
							break;
						} else {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
											  "RecvAndPlayBackPthread: socket disconnect!\n");
							switch_thread_cond_broadcast(vad->cond);
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
											  " RecvAndPlayBackPthread: -------- 失去连接时的signal信号已经发送!!\n");
							switch_mutex_unlock(vad->mutex);
							switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
							break;
						}
					}else{
						ret = recv(vad->cfd, readbuf, sizeof(readbuf), MSG_PEEK|MSG_DONTWAIT);
						if (ret >0 ){
							parse_json = vad_parse_Json(readbuf, vad);
							if (0 == (strcmp(parse_json, "call_end"))){
								switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,"RecvAndPlayBackPthread: when user no sounds vad_parse_Json success call flag is call_end!!\n");
								switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
								break;
							}
						}else{
							switch_sleep(20 * 1000);
						}
                        
                    }
				}
			}
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvAndPlayBackPthread: socket disconnect!\n");
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			break;
		}
	}
	vad->pthread_exit = 2;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "RecvAndPlayBackPthread: pthread is over!");
	return NULL;
}

static switch_bool_t vad_audio_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	switch_vad_docker_t *vad = (switch_vad_docker_t *)user_data;
	switch_core_session_t *session = vad->session;
	switch_frame_t *linear_frame;
	uint32_t linear_len = 0;
	int ret = -1;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	int write_buf_len = -1;
	char dir[6] = "/tmp/";
	//const char *src = ".raw";
	char readbuf[256] = {0};
	char sendbuf[320] = {0};
	char str[7] = {0};
	char *parse_json = NULL;
	char *serialize_json = NULL;
	switch_threadattr_t *thd_attr = NULL;
	// switch_status_t st;

	switch (type) {
	case SWITCH_ABC_TYPE_INIT:
		if ((ret = create_client(vad)) == -1) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "create_client fail\n");
			return SWITCH_FALSE;
		}

		vad->uuid = switch_core_session_get_uuid(session);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "   uuid %s \n", vad->uuid);

		if (globals.isSync == 1) {
			serialize_json = vad_serialize_json(vad, 1);
			if (NULL == serialize_json) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "vad_serialize_json fail!!\n");
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
								  "vad_serialize_json success writebuf is %s\n", serialize_json);
			}

			ret = send(vad->cfd, serialize_json, strlen(serialize_json), 0);
			if (ret <= 0) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
								  "when init send socket data fail errno is :%s!!\n", strerror(errno));
				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			}
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when init send len is :%d!!\n",
							  ret);

			ret = recv(vad->cfd, readbuf, sizeof(readbuf), 0);
			if (ret <= 0) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
								  "recv()  empty data vad no catch :%s!!\n", strerror(errno));
				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "recv readbuf is %s \n",
								  readbuf);
			}

			parse_json = vad_parse_Json(readbuf, vad);
			if (NULL == parse_json) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "vad_parse_Json is NULL!!\n");
				return SWITCH_TRUE;
			} else if (0 == (strcmp(parse_json, "call_end"))) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
								  "vad_parse_Json success call flag is call_end!!\n");
				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
				return SWITCH_TRUE;
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "first connect return: %s\n",
								  parse_json);
			}
		}

		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
						  "Starting VAD detection for audio stream, stop_talk_to_recognition_time is %d,mode "
						  "is %d,no_sound_timeout is %d , sync : %d\n",
						  vad->stop_talk_to_recognition_time, globals.mode, vad->no_sound_timeout, globals.isSync);

		vad->pool = switch_core_session_get_pool(session);

		switch_mutex_init(&vad->mutex, SWITCH_MUTEX_NESTED, vad->pool);
		switch_thread_cond_create(&vad->cond, vad->pool);

		switch_threadattr_create(&thd_attr, vad->pool);
		switch_threadattr_detach_set(thd_attr, 1);
		switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
		switch_thread_create(&vad->thread, thd_attr, RecvAndPlayBackPthread, vad, vad->pool);

		break;
	case SWITCH_ABC_TYPE_CLOSE:

		vad->callend_play++;
		if (globals.isSync == 2) {
			serialize_json = vad_serialize_json(vad, 0);
			if (NULL == serialize_json) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "vad_serialize_json fail!!\n");
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
								  "vad_serialize_json success writebuf is %s\n", serialize_json);
			}
			send(vad->cfd, serialize_json, strlen(serialize_json), 0);
		} else if (globals.isSync == 1) {

			ret = send(vad->cfd, "call_end", strlen("call_end"), 0);
			if (ret <= 0) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
								  "when close send socket data fail errno is :%s!!\n", strerror(errno));
			}
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when close send len is :%d!!\n",
							  ret);
		}
		
		// switch_thread_join(&st, vad->thread);
		close(vad->write_fd);

		if (vad->fvad) {
			fvad_free(vad->fvad);
			vad->fvad = NULL;
		}

		
		while(vad->pthread_exit != 2)
		{
			switch_sleep(20 * 1000);
		}

		close(vad->cfd);
		switch_thread_cond_destroy(vad->cond);
		switch_mutex_destroy(vad->mutex);
		switch_core_media_bug_flush(bug);
		
		// switch_core_session_reset(session, SWITCH_TRUE, SWITCH_TRUE);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "Stopping VAD detection for audio stream\n");
		break;
	case SWITCH_ABC_TYPE_WRITE:
	case SWITCH_ABC_TYPE_WRITE_REPLACE:
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,"读取用户的声音成功\n");
		break;
	case SWITCH_ABC_TYPE_READ:
	case SWITCH_ABC_TYPE_READ_REPLACE:

		/*if ((0 == (strcmp(vad->call_flag, "call_end")))){
			return SWITCH_TRUE;
		}*/

		linear_frame = switch_core_media_bug_get_read_replace_frame(bug);

		linear_len = linear_frame->datalen;

		switch_vad_docker_process(vad, linear_frame->data, linear_len / 2);

		if (vad->vad_state == SWITCH_VAD_STATE_START_TALKING) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "START TALKING\n");
			vad->log_flag = TRUE;
			if (globals.isSync == 2) {
				memset(vad->AudioDir, 0, sizeof(vad->AudioDir));
				memcpy(vad->AudioDir, dir, sizeof(dir));

				strcat(vad->AudioDir, vad->uuid);
				vad->fileflag++;
				//sprintf(str, "%d%s", vad->fileflag, src);
				strcat(vad->AudioDir, str);
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
								  "AudioDir is %s   vad->fileflag is %d\n", vad->AudioDir, vad->fileflag);

				vad->write_fd = open(vad->AudioDir, O_RDWR | O_TRUNC | O_CREAT, 0777);
				if (vad->write_fd == -1) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
									  "open %s file fail errorno is %s\n", vad->AudioDir, strerror(errno));
				}
			}
		} else if (vad->vad_state == SWITCH_VAD_STATE_STOP_TALKING) {
			if (vad->log_flag == FALSE) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "USER STOP TALK\n");
				vad->log_flag = TRUE;
			}

			strcpy(sendbuf, "sentence_end");

			if (globals.isSync == 2) {
				serialize_json = vad_serialize_json(vad, 1);
				if (NULL == serialize_json) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
									  "vad_serialize_json fail!!\n");
				} else {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
									  "vad_serialize_json success writebuf is %s\n", serialize_json);
				}

				send(vad->cfd, serialize_json, strlen(serialize_json), 0);
				close(vad->write_fd);
			} else if (globals.isSync == 1) {
				ret = send(vad->cfd, sendbuf, 320, 0);
				if (ret <= 0) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
									  "when stop send socket data fail errno is :%s!!\n", strerror(errno));
					switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
				}
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when stop send len is :%d!!\n",
								  ret);
			}
		} else if (vad->vad_state == SWITCH_VAD_STATE_TALKING) {
			if (vad->log_flag == TRUE) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "State - USER IS TALKING\n");
			}

			if (globals.isSync == 2) {
				write_buf_len = write(vad->write_fd, linear_frame->data, linear_frame->datalen);
				if (write_buf_len == -1) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
									  "write file fail %d  errorno is %s\n", write_buf_len, strerror(errno));
				}
			} else if (globals.isSync == 1) {
				if (vad->cond_flag == TRUE) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "vad->cond_flag == TRUE \n");
					switch_mutex_lock(vad->mutex);
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "callback上锁了 \n");

					vad->cond_flag = FALSE;
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "vad->cond_flag == FALSE \n");

					switch_thread_cond_timedwait(vad->cond, vad->mutex, 120 * 1000);
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "退出等待状态 \n");

					switch_mutex_unlock(vad->mutex);
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "callback解锁了 \n");
				}
				if (vad->is_playback_end) {
				ret = send(vad->cfd, linear_frame->data, linear_frame->datalen, 0);
				if (ret < 0) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
									  "when talking send socket data fail errno is :%s!!\n", strerror(errno));
					switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
				} else if (ret > 0 && vad->log_flag == TRUE) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
									  "send len is :%d everytime!!\n", ret);
					vad->log_flag = FALSE;
				} else if (ret == 0) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "send frame data lenth is :%d!!\n",
									  ret);
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "no hangup\n");
					//switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
				}
				}
				
			}
		} else if (vad->vad_state == SWITCH_VAD_STATE_NONE) {
			if (vad->log_flag == TRUE) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "State - no sounds\n");
				vad->log_flag = FALSE;
			}

		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "VAD State is error\n");
		}

		break;
	default:
		break;
	}

	return SWITCH_TRUE;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_vad_load)
{
	switch_application_interface_t *app_interface;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	if (load_config()) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, " load_config falil...\n");
		return SWITCH_STATUS_UNLOAD;
	}

	SWITCH_ADD_APP(app_interface, "vad", "Voice activity detection", "Freeswitch's VAD", vad_start_function,
				   "[start|stop]", SAF_NONE);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, " vad_load successful...\n");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_vad_shutdown) { return SWITCH_STATUS_SUCCESS; }

SWITCH_STANDARD_APP(vad_start_function)
{
	switch_status_t status;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_vad_docker_t *s_vad = NULL;
	switch_codec_implementation_t imp = {0};
	int flags = 0;

	if (!zstr(data)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "VAD input parameter %s\n", data);
	}

	if ((s_vad = (switch_vad_docker_t *)switch_channel_get_private(channel, VAD_PRIVATE))) {
		if (!zstr(data) && !strcasecmp(data, "stop")) {
			switch_channel_set_private(channel, VAD_PRIVATE, NULL);
			if (s_vad->read_bug) {
				switch_core_media_bug_remove(session, &s_vad->read_bug);
				s_vad->read_bug = NULL;
				switch_core_session_reset(session, SWITCH_TRUE, SWITCH_TRUE);
			}
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Stopped VAD detection\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
							  "Cannot run vad detection 2 times on the same session!\n");
		}
		return;
	}

	s_vad = switch_core_session_alloc(session, sizeof(*s_vad));
	switch_assert(s_vad);
	memset(s_vad, 0, sizeof(*s_vad));
	s_vad->session = session;

	switch_core_session_raw_read(session);
	switch_core_session_get_read_impl(session, &imp);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Read imp %u %u.\n", imp.samples_per_second,
					  imp.number_of_channels);
	s_vad->sample_rate = imp.samples_per_second ? imp.samples_per_second : 8000;
	s_vad->channels = imp.number_of_channels;

	// just for fvad set!
	switch_vad_docker_init(s_vad);

	flags = SMBF_READ_REPLACE | SMBF_ANSWER_REQ;
	status =
		switch_core_media_bug_add(session, "vad_read", NULL, vad_audio_callback, s_vad, 0, flags, &s_vad->read_bug);

	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "Failed to attach vad to media stream!\n");
		return;
	}

	switch_channel_set_private(channel, VAD_PRIVATE, s_vad);
}