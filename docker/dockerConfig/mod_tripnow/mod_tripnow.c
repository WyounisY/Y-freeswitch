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

static char *tripnow_serialize_json(switch_tripnow_docker_t *tripnow, int callstatus)
{
	cJSON *pJson = NULL;
	char *writebuf = NULL;
	const char *caller_number = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(tripnow->session);
	const char *nlp_type = NULL;

	nlp_type = switch_channel_get_variable(channel, "nlp_type");
	if (!nlp_type) {
		nlp_type = "huoli_model";
	}

	caller_number = switch_channel_get_variable(channel, "caller_id_number");
	if (!caller_number) {
		caller_number = "000000";
	}

	pJson = cJSON_CreateObject();
	if (NULL == pJson) {
		return NULL;
	}

	cJSON_AddStringToObject(pJson, "flag", callstatus == 1 ? "call_start" : "call_end");
	cJSON_AddStringToObject(pJson, "uuid", tripnow->uuid);
	cJSON_AddStringToObject(pJson, "caller_id_number", caller_number);
	cJSON_AddStringToObject(pJson, "nlp_type", nlp_type);
	cJSON_AddStringToObject(pJson, "asr_type", "stream");

	writebuf = cJSON_PrintUnformatted(pJson);
	cJSON_Delete(pJson);

	return writebuf;
}

static int create_client(switch_tripnow_docker_t *g_tripnow)
{
	struct sockaddr_in SockAddr = {0};
	int ret = -1;

	g_tripnow->cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_tripnow->cfd < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create socket\n");
		return g_tripnow->cfd;
	}

	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = htons(PORT);
	inet_pton(AF_INET, ADDR, &SockAddr.sin_addr.s_addr);

	ret = connect(g_tripnow->cfd, (struct sockaddr *)&SockAddr, sizeof(SockAddr));
	if (ret < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "connect failed: %s\n", strerror(errno));
		close(g_tripnow->cfd);
		g_tripnow->cfd = -1;
	}

	return ret;
}

static switch_bool_t switch_tripnow_docker_close(switch_tripnow_docker_t *tripnow)
{
	switch_core_session_t *session = tripnow->session;

	if (tripnow->cfd >= 0) {
		send(tripnow->cfd, "call_end", strlen("call_end"), 0);
		close(tripnow->cfd);
		tripnow->cfd = -1;
	}

	if (tripnow->audio_mutex) {
		switch_mutex_destroy(tripnow->audio_mutex);
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "CALLIN stopped\n");

	return SWITCH_TRUE;
}

static void *SWITCH_THREAD_FUNC RecvPthread(switch_thread_t *thread, void *user_data)
{
	switch_tripnow_docker_t *tripnow = (switch_tripnow_docker_t *)user_data;
	char readbuf[AUDIO_FRAME_SIZE] = {0};
	int ret = -1;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "RecvPthread start\n");

	while (switch_channel_ready(switch_core_session_get_channel(tripnow->session))) {
		ret = recv(tripnow->cfd, readbuf, AUDIO_FRAME_SIZE, 0);
		if (ret <= 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvPthread: socket closed, ret=%d\n", ret);
			tripnow->pthread_exit = TRUE;
			break;
		}

		if (ret == AUDIO_FRAME_SIZE) {
			char *audio_data = (char *)malloc(AUDIO_FRAME_SIZE);
			if (audio_data) {
				memcpy(audio_data, readbuf, AUDIO_FRAME_SIZE);
				if (switch_queue_trypush(tripnow->audio_queue, audio_data) != SWITCH_STATUS_SUCCESS) {
					free(audio_data);
				}
			}
		}

		memset(readbuf, 0, AUDIO_FRAME_SIZE);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "RecvPthread exit\n");
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

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "AudioProcessPthread start\n");

	if (switch_channel_pre_answer(channel) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Channel not answered\n");
		return NULL;
	}

	while (switch_channel_ready(channel) && !tripnow->pthread_exit) {
		status = switch_core_session_read_frame(session, &read_frame, SWITCH_IO_FLAG_NONE, 0);
		if (!SWITCH_READ_ACCEPTABLE(status)) {
			break;
		}

		switch_ivr_parse_all_events(session);

		send_ret = send(tripnow->cfd, read_frame->data, read_frame->datalen, 0);
		if (send_ret < 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "AudioProcessPthread: send failed\n");
			tripnow->pthread_exit = TRUE;
			break;
		}

		if (switch_queue_size(tripnow->audio_queue) >= 1) {
			if (switch_queue_trypop(tripnow->audio_queue, (void **)&pop) == SWITCH_STATUS_SUCCESS && pop != NULL) {
				memcpy(read_frame->data, pop, AUDIO_FRAME_SIZE);
				read_frame->datalen = AUDIO_FRAME_SIZE;
				switch_core_session_write_frame(session, read_frame, SWITCH_IO_FLAG_NONE, 0);
				free(pop);
				pop = NULL;
			}
		}
	}

	tripnow->audio_pthread_exit = TRUE;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "AudioProcessPthread exit\n");
	return NULL;
}

static switch_bool_t switch_tripnow_docker_init(switch_tripnow_docker_t *tripnow)
{
	int ret = -1;
	char readbuf[256] = {0};
	char *serialize_json = NULL;
	switch_threadattr_t *thd_attr = NULL;
	switch_threadattr_t *thd_farm = NULL;
	switch_core_session_t *session = NULL;
	switch_channel_t *channel = NULL;

	tripnow->cfd = -1;
	tripnow->pthread_exit = FALSE;
	tripnow->audio_pthread_exit = FALSE;

	session = tripnow->session;
	channel = switch_core_session_get_channel(session);

	if (NULL == tripnow) {
		return SWITCH_FALSE;
	}

	switch_queue_create(&tripnow->audio_queue, MAX_AUDIO_QUEUE_LEN, switch_core_session_get_pool(session));

	ret = create_client(tripnow);
	if (ret < 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session, SWITCH_LOG_ERROR, "create_client fail\n");
		return SWITCH_FALSE;
	}

	tripnow->uuid = switch_core_session_get_uuid(session);

	serialize_json = tripnow_serialize_json(tripnow, 1);
	if (serialize_json) {
		send(tripnow->cfd, serialize_json, strlen(serialize_json), 0);
		switch_safe_free(serialize_json);
	}

	ret = recv(tripnow->cfd, readbuf, sizeof(readbuf), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session, SWITCH_LOG_ERROR, "recv init response fail\n");
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
		return SWITCH_FALSE;
	}

	tripnow->pool = switch_core_session_get_pool(session);
	switch_mutex_init(&tripnow->audio_mutex, SWITCH_MUTEX_NESTED, tripnow->pool);

	switch_threadattr_create(&thd_attr, tripnow->pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&tripnow->thread, thd_attr, RecvPthread, tripnow, tripnow->pool);

	switch_threadattr_create(&thd_farm, tripnow->pool);
	switch_threadattr_detach_set(thd_farm, 1);
	switch_threadattr_stacksize_set(thd_farm, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&tripnow->audio_thread, thd_farm, AudioProcessPthread, tripnow, tripnow->pool);

	return SWITCH_TRUE;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_tripnow_load)
{
	switch_application_interface_t *app_interface;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_APP(app_interface, "tripnow", "Voice activity detection", "Freeswitch's CALLIN", tripnow_start_function,
				   "[start|stop]", SAF_NONE);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "tripnow_load successful\n");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_tripnow_shutdown)
{
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_STANDARD_APP(tripnow_start_function)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_tripnow_docker_t *s_tripnow = NULL;
	switch_codec_implementation_t imp = {0};
	switch_bool_t init_ret;

	if (!zstr(data)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "tripnow input: %s\n", data);
	}

	if ((s_tripnow = (switch_tripnow_docker_t *)switch_channel_get_private(channel, CALLIN_PRIVATE))) {
		if (!zstr(data) && !strcasecmp(data, "stop")) {
			switch_channel_set_private(channel, CALLIN_PRIVATE, NULL);
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Stopped tripnow\n");
		}
		return;
	}

	s_tripnow = switch_core_session_alloc(session, sizeof(*s_tripnow));
	switch_assert(s_tripnow);
	memset(s_tripnow, 0, sizeof(*s_tripnow));
	s_tripnow->session = session;

	switch_core_session_raw_read(session);
	switch_core_session_get_read_impl(session, &imp);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Read imp %u %u\n", imp.samples_per_second,
					  imp.number_of_channels);

	init_ret = switch_tripnow_docker_init(s_tripnow);
	if (!init_ret) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "tripnow init failed\n");
		return;
	}

	switch_channel_set_private(channel, CALLIN_PRIVATE, s_tripnow);

	while (!s_tripnow->audio_pthread_exit) {
		switch_ivr_parse_all_events(s_tripnow->session);
		switch_sleep(10 * 1000);
	}

	switch_tripnow_docker_close(s_tripnow);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "tripnow session end\n");
}
