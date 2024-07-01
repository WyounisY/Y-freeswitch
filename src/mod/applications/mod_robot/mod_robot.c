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

typedef struct {
	switch_core_session_t *session;
	switch_codec_implementation_t *read_impl;
	switch_media_bug_t *read_bug;
	switch_memory_pool_t *pool;
	int write_fd;
	int cfd;
	int pthread_exit;
	char recv_path[128];
	char call_flag[16];
	char *uuid;
	switch_bool_t log_flag;
	switch_bool_t cond_flag;
	switch_mutex_t *mutex;
	switch_thread_t *thread;
	switch_thread_cond_t *cond;
} switch_vad_docker_t;



static char *vad_serialize_json(switch_vad_docker_t *vad, int callstatus)
{
	cJSON *pJson = NULL;
	char *writebuf = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(vad->session);
	const char *nlp_type = switch_channel_get_variable(channel, "nlp_type");
	if (nlp_type == NULL) {
		nlp_type = "huoli_model";
		// 变量不存在
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "nlp_type变量不存在 !! : %s \n", nlp_type);
	} else {
		// 变量存在并且有值
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "nlp_type变量存在 !! : %s \n", nlp_type);
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
	cJSON_AddStringToObject(pJson, "asr_type", "stream");

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


static switch_bool_t switch_vad_docker_init(switch_vad_docker_t *vad)
{
	if (NULL == vad) return SWITCH_FALSE;

	vad->write_fd = -1;
	vad->cfd = -1;
	vad->log_flag = TRUE;
	vad->uuid = NULL;
	vad->cond_flag = FALSE;

	vad->pthread_exit = 0;
	memset(vad->recv_path, 0, 128);

	return SWITCH_TRUE;
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
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvAndPlayBackPthread phread while 1 %s!\n",
						  vad->uuid);
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

				status = switch_ivr_play_file(vad->session, NULL, vad->recv_path, NULL);
				if (status != SWITCH_STATUS_SUCCESS) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
									  "RecvAndPlayBackPthread: switch_ivr_play_file fail!!\n");
					break;
				}
				// switch_assert(!(fh.flags & SWITCH_FILE_OPEN));

				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);

				break;
			} else if (0 == (strcmp(parse_json, "tts_end"))) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "RecvAndPlayBackPthread: vad_parse_Json success ---- soundfile path is %s\n",
								  parse_json);

				status = switch_ivr_play_file(vad->session, NULL, vad->recv_path, NULL);
				if (status != SWITCH_STATUS_SUCCESS) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
									  "RecvAndPlayBackPthread: switch_ivr_play_file fail!!\n");
					break;
				}
				// switch_assert(!(fh.flags & SWITCH_FILE_OPEN));
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
					// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvAndPlayBackPthread phread while 2
					// %s!\n",vad->uuid);
					if (vad->cond_flag == FALSE) {
						switch_mutex_lock(vad->mutex);

						ret = send(vad->cfd, sendbuf, strlen(sendbuf), 0);
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
					} else {
						ret = recv(vad->cfd, readbuf, sizeof(readbuf), MSG_PEEK | MSG_DONTWAIT);
						if (ret > 0) {
							parse_json = vad_parse_Json(readbuf, vad);
							if (0 == (strcmp(parse_json, "call_end"))) {
								switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
												  "RecvAndPlayBackPthread: when user no sounds vad_parse_Json success "
												  "call flag is call_end!!\n");
								switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
								break;
							}
						} else {
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
	int ret = -1;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	char readbuf[256] = {0};
	char *parse_json = NULL;
	char *serialize_json = NULL;
	switch_threadattr_t *thd_attr = NULL;

	switch (type) {
	case SWITCH_ABC_TYPE_INIT:
		if ((ret = create_client(vad)) == -1) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "create_client fail\n");
			return SWITCH_FALSE;
		}

		vad->uuid = switch_core_session_get_uuid(session);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "   uuid %s \n", vad->uuid);

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
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when init send len is :%d!!\n", ret);

		ret = recv(vad->cfd, readbuf, sizeof(readbuf), 0);
		if (ret <= 0) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
							  "recv()  empty data vad no catch :%s!!\n", strerror(errno));
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "recv readbuf is %s \n", readbuf);
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

		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
						  "Starting VAD detection for audio stream  ");

		vad->pool = switch_core_session_get_pool(session);

		switch_mutex_init(&vad->mutex, SWITCH_MUTEX_NESTED, vad->pool);
		switch_thread_cond_create(&vad->cond, vad->pool);

		switch_threadattr_create(&thd_attr, vad->pool);
		switch_threadattr_detach_set(thd_attr, 1);
		switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
		switch_thread_create(&vad->thread, thd_attr, RecvAndPlayBackPthread, vad, vad->pool);

		break;
	case SWITCH_ABC_TYPE_CLOSE:

		ret = send(vad->cfd, "call_end", strlen("call_end"), 0);
		if (ret <= 0) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
							  "when close send socket data fail errno is :%s!!\n", strerror(errno));
		}
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when close send len is :%d!!\n", ret);

		// switch_thread_join(&st, vad->thread);
		close(vad->write_fd);

		close(vad->cfd);
		while (vad->pthread_exit != 2) { switch_sleep(20 * 1000); }

		switch_thread_cond_destroy(vad->cond);
		switch_mutex_destroy(vad->mutex);
		switch_core_media_bug_flush(bug);

		// switch_core_session_reset(session, SWITCH_TRUE, SWITCH_TRUE);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "Stopping VAD detection for audio stream\n");
		break;
	case SWITCH_ABC_TYPE_WRITE:
	case SWITCH_ABC_TYPE_WRITE_REPLACE:
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "读取用户的声音成功\n");
		break;
	case SWITCH_ABC_TYPE_READ:
	case SWITCH_ABC_TYPE_READ_REPLACE:

		linear_frame = switch_core_media_bug_get_read_replace_frame(bug);

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

		ret = send(vad->cfd, linear_frame->data, linear_frame->datalen, 0);
		if (ret < 0) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
							  "when talking send socket data fail errno is :%s!!\n", strerror(errno));
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
		} else if (ret > 0) {
			if (vad->log_flag == TRUE) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "send len is :%d everytime!!\n",
								  ret);
				vad->log_flag = FALSE;
			}

		} else if (ret == 0) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "send frame data lenth is :%d!!\n",
							  ret);
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "no hangup\n");
			// switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "发送语音流时发生未知错错误 %d\n",
							  ret);
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