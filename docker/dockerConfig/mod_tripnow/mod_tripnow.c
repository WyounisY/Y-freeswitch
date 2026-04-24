#include <switch.h>
#include <sys/time.h>

#define CALLIN_PRIVATE "_tripnow_"		  // tripnow模块哈希key值
#define CALLIN_XML_CONFIG "tripnow.conf" // 配置文件名
#define PORT 8020				  // 目标地址端口号
#define ADDR "127.0.0.1"		  // 目标地址IP
#define MAX_SOCKET_QUEUE_LEN 1
#define MAX_AUDIO_QUEUE_LEN 3000
#define ADD_SIZE 4

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_tripnow_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_tripnow_load);
SWITCH_MODULE_DEFINITION(mod_tripnow, mod_tripnow_load, mod_tripnow_shutdown, NULL);
SWITCH_STANDARD_APP(tripnow_start_function);

typedef struct {
	// 维护整个通话的session 会话变量
	switch_core_session_t *session;
	// 编码信息 音频数据的详细信息
	switch_codec_implementation_t *read_impl;
	// 放在这通电话上的media bug
	switch_media_bug_t *read_bug;
	// 通话的内存池
	switch_memory_pool_t *pool;
	// socket 连接符
	int cfd;
	// 判断线程是否退出 true是退出 false是没有退出
	switch_bool_t pthread_exit;
	switch_bool_t audio_pthread_exit;
	// 该段音频文件中的数据是否播放完毕 true是播放完毕 false是没有播放完毕
	switch_bool_t is_playback_end;
	// 这条腿的uuid
	char *uuid;
	// 打印log true 打印 false 不打印
	switch_bool_t log_flag;
	// 判断是否继续播放音频   true 可以继续播放 false 被打断不能继续播放
	switch_bool_t iscontiue_flag;
	// 处理socket接收线程变量
	switch_thread_t *thread;
	// 处理音频获取和播放的线程变量
	switch_thread_t *audio_thread;
	// 音频锁 主要针对iscontiue_flag
	switch_mutex_t *audio_mutex;
	// 音频数据队列
	switch_queue_t *audio_queue;
	// 测试文件描述符
	// int test_file;
	// 尝试次数
	int retry_count;
} switch_tripnow_docker_t;

// 动态音频帧结构体
typedef struct {
	void *data;
	int size;
} audio_frame_t;

static char *tripnow_serialize_json(switch_tripnow_docker_t *tripnow, int callstatus)
{
	cJSON *pJson = NULL;
	char *writebuf = NULL;
	const char *caller_number = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(tripnow->session);
	const char *nlp_type = NULL;

	// 获取nlp_type
	nlp_type = switch_channel_get_variable(channel, "nlp_type");
	if (!nlp_type) {
		nlp_type = "huoli_model";
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "nlp_type变量不存在 !! : %s \n", nlp_type);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "nlp_type变量存在 !! : %s \n", nlp_type);
	}

	caller_number = switch_channel_get_variable(channel, "caller_id_number");
	if (!caller_number) {
		caller_number = "000000";
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "caller_number变量不存在 !! : %s \n", caller_number);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "caller_number变量存在 !! : %s \n", caller_number);
	}

	pJson = cJSON_CreateObject();
	if (NULL == pJson) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "cJSON_CreateObject Failed !!\n");
		return NULL;
	}

	cJSON_AddStringToObject(pJson, "flag", callstatus == 1 ? "call_start" : "call_end");
	cJSON_AddStringToObject(pJson, "uuid", tripnow->uuid);
	cJSON_AddStringToObject(pJson, "caller_id_number", caller_number);
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

/**
 * 创建客户端并连接到服务器。
 * @param g_tripnow 指向 switch_tripnow_docker_t 结构体的指针。
 * @return 成功返回 0，失败返回负值。
 */
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

	if (0 > (ret = connect(g_tripnow->cfd, (struct sockaddr *)&SockAddr, sizeof(SockAddr)))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, " errorno is %s  \n", strerror(errno));
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "connect server success!!! \n");
	}

	return ret;
}

/**
 * 关闭 CALLIN Docker 函数
 *
 * @param tripnow 输入的指向需要初始化的 switch_tripnow_docker_t 结构体的指针。
 * @return 返回一个 switch_bool_t 值，表示初始化是否成功。
 */
static switch_bool_t switch_tripnow_docker_close(switch_tripnow_docker_t *tripnow)
{
	int ret = -1;
	switch_core_session_t *session = tripnow->session;
	ret = send(tripnow->cfd, "call_end", strlen("call_end"), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "when close send socket data fail errno is :%s!!\n", strerror(errno));
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when close send len is :%d!!\n", ret);

	// switch_thread_join(&st, tripnow->thread);

	close(tripnow->cfd);

	switch_mutex_destroy(tripnow->audio_mutex);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
					  "Stopping CALLIN detection for audio stream\n");
	return SWITCH_TRUE;
}


/**
 * 处理接收线程的函数。
 * @param thread 指向 switch_thread_t 结构的指针。
 * @param user_data 用户数据的指针。
 * @return 返回处理后的数据指针。
 */
static void *SWITCH_THREAD_FUNC RecvPthread(switch_thread_t *thread, void *user_data)
{
	switch_tripnow_docker_t *tripnow = (switch_tripnow_docker_t *)user_data;
	char readbuf[4096] = {0};
	int ret = -1;
	switch_channel_t *channel = switch_core_session_get_channel(tripnow->session);
	void *dummy = NULL;
	audio_frame_t *audio_frame = NULL;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "----------------RecvPthread start !!----------------\n");

	while (switch_channel_ready(channel)) {
		ret = recv(tripnow->cfd, readbuf, sizeof(readbuf), 0);
		if (ret < 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvPthread: recv() fail errno: %s!!\n",
							  strerror(errno));
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			break;
		} else if (ret == 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvPthread: socket disconnect!\n");
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			break;
		} else if (ret > 0) {
			tripnow->log_flag = TRUE;

			// 清空 audio_queue
			switch_mutex_lock(tripnow->audio_mutex);
			dummy = NULL;
			while (switch_queue_size(tripnow->audio_queue) >= 1) {
				if (switch_queue_trypop(tripnow->audio_queue, &dummy) == SWITCH_STATUS_SUCCESS && dummy != NULL) {
					audio_frame_t *frame = (audio_frame_t *)dummy;
					if (frame->data) {
						free(frame->data);
					}
					free(frame);
				}
			}
			switch_mutex_unlock(tripnow->audio_mutex);

			// Go发送音频流数据，C直接放入播放队列（动态大小）
			audio_frame = (audio_frame_t *)malloc(sizeof(audio_frame_t));
			if (audio_frame) {
				audio_frame->data = malloc(ret);
				if (audio_frame->data) {
					memcpy(audio_frame->data, readbuf, ret);
					audio_frame->size = ret;
					while (switch_queue_trypush(tripnow->audio_queue, audio_frame) != SWITCH_STATUS_SUCCESS) {
						if (tripnow->retry_count >= 3) {
							tripnow->retry_count = 0;
							break;
						}
						tripnow->retry_count++;
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "push audio_queue 失败\n");
					}
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "接收到Go发送的音频流并放入播放队列, 大小: %d\n", ret);
				} else {
					free(audio_frame);
					audio_frame = NULL;
				}
			}

			switch_mutex_lock(tripnow->audio_mutex);
			tripnow->iscontiue_flag = TRUE;
			switch_mutex_unlock(tripnow->audio_mutex);

		}
		memset(readbuf, 0, sizeof(readbuf));

		if (tripnow->audio_pthread_exit) { break; }
	}
	tripnow->pthread_exit = TRUE;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "RecvPthread: pthread is over!\n");
	return NULL;
}

/**
 * 处理接收线程的函数。
 * @param thread 指向 switch_thread_t 结构的指针。
 * @param user_data 用户数据的指针。
 * @return 返回处理后的数据指针。
 */
static void *SWITCH_THREAD_FUNC AudioProcessPthread(switch_thread_t *thread, void *user_data)
{
	switch_tripnow_docker_t *tripnow = (switch_tripnow_docker_t *)user_data;
	switch_channel_t *channel = switch_core_session_get_channel(tripnow->session);
	switch_status_t status;
	switch_frame_t *read_frame;
	switch_core_session_t *session = tripnow->session;
	int ret = -1;
	void *pop = NULL;
	unsigned int audio_size = 0;
	audio_frame_t *frame = NULL;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
					  "----------------AudioProcessPthread start !!----------------\n");

	if (switch_channel_pre_answer(channel) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "通话未被接听，线程退出\n");
		return NULL;
	}

	while (switch_channel_ready(channel)) {
		status = switch_core_session_read_frame(session, &read_frame, SWITCH_IO_FLAG_NONE, 0);
		if (!SWITCH_READ_ACCEPTABLE(status)) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "读取是数据帧出错");
			break;
		}
		switch_ivr_parse_all_events(session);
		// 线程退出不再发送音频数据
		if (!tripnow->pthread_exit) {
			ret = send(tripnow->cfd, read_frame->data, read_frame->datalen, 0);
			if (ret < 0) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
								  "when talking send socket data fail errno is :%s!!\n", strerror(errno));
				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			} else if (ret > 0) {
				if (tripnow->log_flag == TRUE) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
									  "send len is :%d everytime!!\n", ret);
					tripnow->log_flag = FALSE;
				}
			} else {
				// ret == 0 表示暂时无法发送，可能是缓冲区满，下次循环继续发送即可，不打印日志
			}
		}

		switch_mutex_lock(tripnow->audio_mutex);
		if (tripnow->iscontiue_flag) {
			if (tripnow->log_flag == TRUE) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "获取音频队列的开关打开 \n");
			}
			audio_size = switch_queue_size(tripnow->audio_queue);
			if (audio_size >= 1) {
				// 播放开始标志
				tripnow->is_playback_end = FALSE;
				if (tripnow->log_flag == TRUE) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
									  "音频队列的数据大于等于1 %d \n", audio_size);
					tripnow->log_flag = FALSE;
				}
				switch_queue_pop(tripnow->audio_queue, &pop);

				// 使用动态音频帧结构体
				frame = (audio_frame_t *)pop;
				if (frame && frame->data && frame->size > 0) {
					// 复制实际大小的音频数据到frame
					memcpy(read_frame->data, frame->data, frame->size);
					read_frame->datalen = frame->size;

					switch_core_session_write_frame(tripnow->session, read_frame, SWITCH_IO_FLAG_NONE, 0);

					// 释放音频帧内存
					free(frame->data);
					free(frame);
				}
				pop = NULL;
			} else {
			}
		}
		switch_mutex_unlock(tripnow->audio_mutex);

		if (tripnow->pthread_exit && tripnow->is_playback_end) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "检测到接收线程退出，挂断电话。\n");
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
		}

		if (switch_channel_test_flag(channel, CF_BREAK)) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, " CF_BREAK 标志位设置，挂断电话。\n");
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			switch_channel_clear_flag(channel, CF_BREAK);
			break;
		}
	}
	tripnow->audio_pthread_exit = TRUE;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "AudioProcessPthread: pthread is over!\n");
	return NULL;
}

/**
 * 初始化 CALLIN Docker 结构体。
 *
 * @param tripnow 输入的指向需要初始化的 switch_tripnow_docker_t 结构体的指针。
 * @return 返回一个 switch_bool_t 值，表示初始化是否成功。
 */
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
	tripnow->log_flag = TRUE;
	tripnow->uuid = NULL;
	tripnow->pthread_exit = FALSE;
	tripnow->iscontiue_flag = FALSE;
	tripnow->is_playback_end = FALSE;
	tripnow->audio_pthread_exit = FALSE;
	tripnow->retry_count = 0;

	session = tripnow->session;
	channel = switch_core_session_get_channel(session);

	if (NULL == tripnow) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "tripnow为NULL");
		return SWITCH_FALSE;
	}

	switch_queue_create(&tripnow->audio_queue, MAX_AUDIO_QUEUE_LEN, switch_core_session_get_pool(tripnow->session));

	// 初始化
	if ((ret = create_client(tripnow)) == -1) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "create_client fail\n");
		return SWITCH_FALSE;
	}

	tripnow->uuid = switch_core_session_get_uuid(session);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "这通电话的uuid: %s \n", tripnow->uuid);

	serialize_json = tripnow_serialize_json(tripnow, 1);
	if (NULL == serialize_json) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "tripnow_serialize_json fail!!\n");
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
						  "tripnow_serialize_json success writebuf is %s\n", serialize_json);
	}

	ret = send(tripnow->cfd, serialize_json, strlen(serialize_json), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "when init send socket data fail errno is :%s!!\n", strerror(errno));
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when init send len is :%d!!\n", ret);

	ret = recv(tripnow->cfd, readbuf, sizeof(readbuf), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "recv()  empty data tripnow no catch :%s!!\n", strerror(errno));
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "recv readbuf is %s \n", readbuf);
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
					  "Starting CALLIN detection for audio stream  ");

	tripnow->pool = switch_core_session_get_pool(session);

	// 在初始化代码中创建互斥锁
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

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, " tripnow_load successful...\n");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_tripnow_shutdown) { return SWITCH_STATUS_SUCCESS; }

SWITCH_STANDARD_APP(tripnow_start_function)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_tripnow_docker_t *s_tripnow = NULL;
	switch_codec_implementation_t imp = {0};
	switch_bool_t ret;

	if (!zstr(data)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "CallIn input parameter %s\n", data);
	}

	if ((s_tripnow = (switch_tripnow_docker_t *)switch_channel_get_private(channel, CALLIN_PRIVATE))) {
		if (!zstr(data) && !strcasecmp(data, "stop")) {
			switch_channel_set_private(channel, CALLIN_PRIVATE, NULL);
			if (s_tripnow->read_bug) {
				switch_core_media_bug_remove(session, &s_tripnow->read_bug);
				s_tripnow->read_bug = NULL;
				switch_core_session_reset(session, SWITCH_TRUE, SWITCH_TRUE);
			}
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Stopped CALLIN detection\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
							  "Cannot run tripnow detection 2 times on the same session!\n");
		}
		return;
	}

	s_tripnow = switch_core_session_alloc(session, sizeof(*s_tripnow));
	switch_assert(s_tripnow);
	memset(s_tripnow, 0, sizeof(*s_tripnow));
	s_tripnow->session = session;

	switch_core_session_raw_read(session);
	switch_core_session_get_read_impl(session, &imp);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Read imp %u %u.\n", imp.samples_per_second,
					  imp.number_of_channels);

	ret = switch_tripnow_docker_init(s_tripnow);
	if (!ret) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "程序初始化失败，结束通话\n");
		return;
	}

	switch_channel_set_private(channel, CALLIN_PRIVATE, s_tripnow);

	while (!s_tripnow->audio_pthread_exit) {
    // 必须加这行，让FreeSWITCH处理挂断事件
    switch_ivr_parse_all_events(s_tripnow->session);
    switch_sleep(10 * 1000);
}
	ret = switch_tripnow_docker_close(s_tripnow);
	if (!ret) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "程序初始化失败，结束通话\n");
		return;
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "当前通话任务结束\n");
}
