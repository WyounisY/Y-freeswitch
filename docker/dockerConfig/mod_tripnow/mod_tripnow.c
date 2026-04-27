#include <switch.h>
#include <sys/time.h>

#define CALLIN_PRIVATE "_tripnow_"
#define CALLIN_XML_CONFIG "tripnow.conf"
#define PORT 8020
#define ADDR "127.0.0.1"
#define MAX_AUDIO_QUEUE_LEN 3000
#define AUDIO_FRAME_SIZE 320

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_tripnow_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_tripnow_load);
SWITCH_MODULE_DEFINITION(mod_tripnow, mod_tripnow_load, mod_tripnow_shutdown, NULL);
SWITCH_STANDARD_APP(tripnow_start_function);

typedef struct {
	switch_core_session_t *session;
	switch_memory_pool_t *pool;
	int cfd;
	switch_bool_t pthread_exit;
	switch_bool_t audio_pthread_exit;
	char *uuid;
	switch_thread_t *thread;
	switch_thread_t *audio_thread;
	switch_mutex_t *audio_mutex;
	switch_queue_t *audio_queue;
} switch_tripnow_docker_t;

static int tripnow_send_all(int fd, const void *buf, size_t len)
{
	const char *p = (const char *)buf;
	size_t sent = 0;

	while (sent < len) {
		ssize_t n = send(fd, p + sent, len - sent, 0);
		if (n <= 0) {
			return -1;
		}
		sent += (size_t)n;
	}

	return 0;
}

static char *tripnow_serialize_json(switch_tripnow_docker_t *tripnow, int callstatus)
{
	cJSON *pJson = NULL;
	char *writebuf = NULL;
	const char *caller_number = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(tripnow->session);
	const char *nlp_type = NULL;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "tripnow_serialize_json: callstatus=%d\n", callstatus);

	nlp_type = switch_channel_get_variable(channel, "nlp_type");
	if (!nlp_type) {
		nlp_type = "huoli_model";
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "tripnow_serialize_json: nlp_type not set, using default: %s\n", nlp_type);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "tripnow_serialize_json: nlp_type=%s\n", nlp_type);
	}

	caller_number = switch_channel_get_variable(channel, "caller_id_number");
	if (!caller_number) {
		caller_number = "000000";
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "tripnow_serialize_json: caller_number not set, using default: %s\n", caller_number);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "tripnow_serialize_json: caller_number=%s\n", caller_number);
	}

	pJson = cJSON_CreateObject();
	if (NULL == pJson) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_ERROR, "tripnow_serialize_json: cJSON_CreateObject failed\n");
		return NULL;
	}

	cJSON_AddStringToObject(pJson, "flag", callstatus == 1 ? "call_start" : "call_end");
	cJSON_AddStringToObject(pJson, "uuid", tripnow->uuid);
	cJSON_AddStringToObject(pJson, "caller_id_number", caller_number);
	cJSON_AddStringToObject(pJson, "nlp_type", nlp_type);
	cJSON_AddStringToObject(pJson, "asr_type", "stream");

	writebuf = cJSON_PrintUnformatted(pJson);
	cJSON_Delete(pJson);

	if (writebuf) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "tripnow_serialize_json: json=%s\n", writebuf);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_ERROR, "tripnow_serialize_json: cJSON_PrintUnformatted failed\n");
	}

	return writebuf;
}

static int create_client(switch_tripnow_docker_t *g_tripnow)
{
	struct sockaddr_in SockAddr = {0};
	int ret = -1;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(g_tripnow->session), SWITCH_LOG_INFO, "create_client: creating socket\n");

	g_tripnow->cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_tripnow->cfd < 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(g_tripnow->session), SWITCH_LOG_ERROR, "create_client: socket() failed, errno=%s\n", strerror(errno));
		return g_tripnow->cfd;
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(g_tripnow->session), SWITCH_LOG_INFO, "create_client: socket created, cfd=%d\n", g_tripnow->cfd);

	memset(&SockAddr, 0, sizeof(SockAddr));
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = htons(PORT);
	inet_pton(AF_INET, ADDR, &SockAddr.sin_addr.s_addr);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(g_tripnow->session), SWITCH_LOG_INFO, "create_client: connecting to %s:%d\n", ADDR, PORT);

	ret = connect(g_tripnow->cfd, (struct sockaddr *)&SockAddr, sizeof(SockAddr));
	if (ret < 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(g_tripnow->session), SWITCH_LOG_ERROR, "create_client: connect() failed, errno=%s\n", strerror(errno));
		close(g_tripnow->cfd);
		g_tripnow->cfd = -1;
		return ret;
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(g_tripnow->session), SWITCH_LOG_INFO, "create_client: connect() success\n");

	return ret;
}

static switch_bool_t switch_tripnow_docker_close(switch_tripnow_docker_t *tripnow)
{
	switch_core_session_t *session = tripnow->session;
	void *pop = NULL;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_close: starting close\n");
	tripnow->pthread_exit = TRUE;
	tripnow->audio_pthread_exit = TRUE;

	if (tripnow->cfd >= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_close: sending call_end to Go\n");
		tripnow_send_all(tripnow->cfd, "call_end\n", strlen("call_end\n"));

		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_close: closing socket cfd=%d\n", tripnow->cfd);
		close(tripnow->cfd);
		tripnow->cfd = -1;
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_close: cfd already invalid\n");
	}

	if (tripnow->audio_mutex) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_close: destroying audio_mutex\n");
		switch_mutex_destroy(tripnow->audio_mutex);
	}

	if (tripnow->audio_queue) {
		while (switch_queue_trypop(tripnow->audio_queue, &pop) == SWITCH_STATUS_SUCCESS && pop != NULL) {
			free(pop);
			pop = NULL;
		}
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_close: completed\n");

	return SWITCH_TRUE;
}

static void *SWITCH_THREAD_FUNC RecvPthread(switch_thread_t *thread, void *user_data)
{
	switch_tripnow_docker_t *tripnow = (switch_tripnow_docker_t *)user_data;
	char readbuf[AUDIO_FRAME_SIZE] = {0};
	char framebuf[AUDIO_FRAME_SIZE] = {0};
	int ret = -1;
	int frame_count = 0;
	int pending = 0;
	char *audio_data = NULL;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "RecvPthread: thread started\n");

	while (switch_channel_ready(switch_core_session_get_channel(tripnow->session))) {
		ret = recv(tripnow->cfd, readbuf, AUDIO_FRAME_SIZE, 0);

		if (ret < 0) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_ERROR, "RecvPthread: recv() failed, errno=%s, setting pthread_exit=TRUE\n", strerror(errno));
			tripnow->pthread_exit = TRUE;
			break;
		} else if (ret == 0) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_ERROR, "RecvPthread: socket disconnected, ret=0, setting pthread_exit=TRUE\n");
			tripnow->pthread_exit = TRUE;
			break;
		} else if (ret > 0) {
			int offset = 0;
			while (offset < ret) {
				int copy = AUDIO_FRAME_SIZE - pending;
				if (copy > (ret - offset)) {
					copy = ret - offset;
				}

				memcpy(framebuf + pending, readbuf + offset, copy);
				pending += copy;
				offset += copy;

				if (pending == AUDIO_FRAME_SIZE) {
					frame_count++;
					if (frame_count <= 10 || frame_count % 100 == 0) {
						switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "RecvPthread: assembled frame #%d, size=%d bytes\n", frame_count, AUDIO_FRAME_SIZE);
					}

					audio_data = (char *)malloc(AUDIO_FRAME_SIZE);
					if (audio_data) {
						memcpy(audio_data, framebuf, AUDIO_FRAME_SIZE);

						if (switch_queue_trypush(tripnow->audio_queue, audio_data) != SWITCH_STATUS_SUCCESS) {
							switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_ERROR, "RecvPthread: queue push failed, frame #%d, freeing memory\n", frame_count);
							free(audio_data);
						} else {
							if (frame_count <= 10) {
								switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "RecvPthread: frame #%d pushed to queue, queue_size=%d\n", frame_count, switch_queue_size(tripnow->audio_queue));
							}
						}
						audio_data = NULL;
					} else {
						switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_ERROR, "RecvPthread: malloc failed for frame #%d\n", frame_count);
					}

					pending = 0;
				}
			}
		}
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "RecvPthread: thread exiting, total_frames=%d, pthread_exit=%d\n", frame_count, tripnow->pthread_exit);
	return NULL;
}

static void *SWITCH_THREAD_FUNC AudioProcessPthread(switch_thread_t *thread, void *user_data)
{
	switch_tripnow_docker_t *tripnow = (switch_tripnow_docker_t *)user_data;
	switch_channel_t *channel = switch_core_session_get_channel(tripnow->session);
	switch_status_t status;
	switch_frame_t *read_frame;
	switch_core_session_t *session = tripnow->session;
	int send_ret = -1;
	char *pop = NULL;
	int send_count = 0;
	int playback_count = 0;
	int queue_size = 0;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "AudioProcessPthread: thread started\n");

	if (switch_channel_pre_answer(channel) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "AudioProcessPthread: switch_channel_pre_answer failed\n");
		return NULL;
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "AudioProcessPthread: channel pre-answer success\n");

	while (switch_channel_ready(channel) && !tripnow->pthread_exit) {
		status = switch_core_session_read_frame(session, &read_frame, SWITCH_IO_FLAG_NONE, 0);
		if (!SWITCH_READ_ACCEPTABLE(status)) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "AudioProcessPthread: read_frame failed, status=%d\n", status);
			break;
		}

		switch_ivr_parse_all_events(session);

		send_ret = tripnow_send_all(tripnow->cfd, read_frame->data, read_frame->datalen);
		if (send_ret < 0) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "AudioProcessPthread: send() failed, errno=%s, setting pthread_exit=TRUE\n", strerror(errno));
			tripnow->pthread_exit = TRUE;
			break;
		} else {
			send_count++;
			if (send_count <= 10 || send_count % 200 == 0) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "AudioProcessPthread: send #%d, sent_bytes=%d\n", send_count, read_frame->datalen);
			}
		}

		queue_size = switch_queue_size(tripnow->audio_queue);
		if (queue_size >= 1) {
			if (switch_queue_trypop(tripnow->audio_queue, (void **)&pop) == SWITCH_STATUS_SUCCESS && pop != NULL) {
				memcpy(read_frame->data, pop, AUDIO_FRAME_SIZE);
				read_frame->datalen = AUDIO_FRAME_SIZE;
				switch_core_session_write_frame(session, read_frame, SWITCH_IO_FLAG_NONE, 0);
				free(pop);
				pop = NULL;

				playback_count++;
				if (playback_count <= 10 || playback_count % 200 == 0) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "AudioProcessPthread: playback #%d, queue_size_before=%d\n", playback_count, queue_size);
				}
			} else {
				if (send_count <= 10) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "AudioProcessPthread: queue pop failed, queue_size=%d\n", queue_size);
				}
			}
		}
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "AudioProcessPthread: thread exiting, send_count=%d, playback_count=%d, pthread_exit=%d\n", send_count, playback_count, tripnow->pthread_exit);

	tripnow->audio_pthread_exit = TRUE;
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "AudioProcessPthread: audio_pthread_exit set to TRUE\n");

	return NULL;
}

static switch_bool_t switch_tripnow_docker_init(switch_tripnow_docker_t *tripnow)
{
	int ret = -1;
	char readbuf[4096] = {0};
	char *serialize_json = NULL;
	switch_threadattr_t *thd_attr = NULL;
	switch_threadattr_t *thd_farm = NULL;
	switch_core_session_t *session = NULL;
	ssize_t total_recv = 0;
	ssize_t n = 0;

	if (NULL == tripnow) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_tripnow_docker_init: tripnow is NULL\n");
		return SWITCH_FALSE;
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tripnow->session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: starting initialization\n");

	tripnow->cfd = -1;
	tripnow->pthread_exit = FALSE;
	tripnow->audio_pthread_exit = FALSE;

	session = tripnow->session;
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: creating audio_queue, max_len=%d\n", MAX_AUDIO_QUEUE_LEN);

	switch_queue_create(&tripnow->audio_queue, MAX_AUDIO_QUEUE_LEN, switch_core_session_get_pool(session));
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: audio_queue created\n");

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: calling create_client\n");
	ret = create_client(tripnow);
	if (ret < 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "switch_tripnow_docker_init: create_client failed, ret=%d\n", ret);
		return SWITCH_FALSE;
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: create_client success, cfd=%d\n", tripnow->cfd);

	tripnow->uuid = switch_core_session_get_uuid(session);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: uuid=%s\n", tripnow->uuid);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: serializing json\n");
	serialize_json = tripnow_serialize_json(tripnow, 1);
	if (serialize_json) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: sending json to Go\n");
		// 发送JSON并加上换行符作为分隔符
		tripnow_send_all(tripnow->cfd, serialize_json, strlen(serialize_json));
		tripnow_send_all(tripnow->cfd, "\n", 1);
		switch_safe_free(serialize_json);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "switch_tripnow_docker_init: serialize_json failed\n");
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: waiting for Go response\n");
	while (total_recv < sizeof(readbuf) - 1) {
		n = recv(tripnow->cfd, readbuf + total_recv, sizeof(readbuf) - 1 - total_recv, 0);
		if (n < 0) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "switch_tripnow_docker_init: recv() failed, errno=%s\n", strerror(errno));
			switch_channel_hangup(switch_core_session_get_channel(session), SWITCH_CAUSE_NORMAL_CLEARING);
			return SWITCH_FALSE;
		} else if (n == 0) {
			readbuf[total_recv] = '\0';
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "switch_tripnow_docker_init: connection closed by Go, received: %s\n", readbuf);
			break;
		}
		total_recv += n;
		if (readbuf[total_recv - 1] == '\n' || readbuf[total_recv - 1] == '\r') {
			break;
		}
	}
	if (total_recv == 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "switch_tripnow_docker_init: recv response failed, ret=0, errno=Success\n");
		switch_channel_hangup(switch_core_session_get_channel(session), SWITCH_CAUSE_NORMAL_CLEARING);
		return SWITCH_FALSE;
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: received response from Go: %s\n", readbuf);

	tripnow->pool = switch_core_session_get_pool(session);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: initializing audio_mutex\n");
	switch_mutex_init(&tripnow->audio_mutex, SWITCH_MUTEX_NESTED, tripnow->pool);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: audio_mutex initialized\n");

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: creating RecvPthread\n");
	switch_threadattr_create(&thd_attr, tripnow->pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&tripnow->thread, thd_attr, RecvPthread, tripnow, tripnow->pool);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: RecvPthread created\n");

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: creating AudioProcessPthread\n");
	switch_threadattr_create(&thd_farm, tripnow->pool);
	switch_threadattr_detach_set(thd_farm, 1);
	switch_threadattr_stacksize_set(thd_farm, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&tripnow->audio_thread, thd_farm, AudioProcessPthread, tripnow, tripnow->pool);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: AudioProcessPthread created\n");

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "switch_tripnow_docker_init: initialization completed successfully\n");

	return SWITCH_TRUE;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_tripnow_load)
{
	switch_application_interface_t *app_interface;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_APP(app_interface, "tripnow", "Voice activity detection", "Freeswitch's CALLIN", tripnow_start_function,
				   "[start|stop]", SAF_NONE);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "mod_tripnow: tripnow_load successful\n");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_tripnow_shutdown)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "mod_tripnow: tripnow_shutdown called\n");
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_STANDARD_APP(tripnow_start_function)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_tripnow_docker_t *s_tripnow = NULL;
	switch_codec_implementation_t imp = {0};
	switch_bool_t init_ret;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: called with data=%s\n", data ? data : "NULL");

	if ((s_tripnow = (switch_tripnow_docker_t *)switch_channel_get_private(channel, CALLIN_PRIVATE))) {
		if (!zstr(data) && !strcasecmp(data, "stop")) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: stop command received\n");
			switch_tripnow_docker_close(s_tripnow);
			switch_channel_set_private(channel, CALLIN_PRIVATE, NULL);
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: tripnow stopped\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "tripnow_start_function: tripnow already running on this session\n");
		}
		return;
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: allocating tripnow structure\n");
	s_tripnow = switch_core_session_alloc(session, sizeof(*s_tripnow));
	switch_assert(s_tripnow);
	memset(s_tripnow, 0, sizeof(*s_tripnow));
	s_tripnow->session = session;

	switch_core_session_raw_read(session);
	switch_core_session_get_read_impl(session, &imp);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: codec - samples_per_second=%u, number_of_channels=%u\n", imp.samples_per_second, imp.number_of_channels);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: calling switch_tripnow_docker_init\n");
	init_ret = switch_tripnow_docker_init(s_tripnow);
	if (!init_ret) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "tripnow_start_function: switch_tripnow_docker_init failed\n");
		return;
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: switch_tripnow_docker_init success\n");

	switch_channel_set_private(channel, CALLIN_PRIVATE, s_tripnow);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: waiting for audio threads to complete\n");

	while (!s_tripnow->audio_pthread_exit) {
		switch_ivr_parse_all_events(s_tripnow->session);
		switch_sleep(10 * 1000);
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: audio threads exited, calling switch_tripnow_docker_close\n");

	switch_tripnow_docker_close(s_tripnow);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow_start_function: tripnow session completed\n");
}
