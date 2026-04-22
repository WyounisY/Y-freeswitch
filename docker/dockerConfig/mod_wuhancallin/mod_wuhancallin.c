#include <switch.h>
#include <sys/time.h>

#define CALLIN_PRIVATE "_wuhancallin_"		  // wuhancallin模块哈希key值
#define CALLIN_XML_CONFIG "wuhancallin.conf" // 配置文件名
#define PORT 8015				  // 目标地址端口号
#define ADDR "127.0.0.1"		  // 目标地址IP
#define MAX_SOCKET_QUEUE_LEN 1
#define MAX_AUDIO_QUEUE_LEN 3000
#define ADD_SIZE 4

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_wuhancallin_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_wuhancallin_load);
SWITCH_MODULE_DEFINITION(mod_wuhancallin, mod_wuhancallin_load, mod_wuhancallin_shutdown, NULL);
SWITCH_STANDARD_APP(wuhancallin_start_function);

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
	// 发送 “playback_end” 缓冲区
	char sendbuf[32];
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
} switch_wuhancallin_docker_t;

// 定义 RIFF Chunk 和 Subchunk 的结构
typedef struct {
	char chunkID[4]; // RIFF
	unsigned int chunkSize;
	char format[4]; // WAVE
} RIFFHeader;

typedef struct {
	char subchunk1ID[4]; // "fmt "
	unsigned int subchunk1Size;
	unsigned short audioFormat;
	unsigned short numChannels;
	unsigned int sampleRate;
	unsigned int byteRate;
	unsigned short blockAlign;
	unsigned short bitsPerSample;
} FmtSubchunk;

typedef struct {
	char subchunk2ID[4]; // "data"
	unsigned int subchunk2Size;
} DataSubchunk;

/**
 * 解析 JSON 数据并返回 cJSON 对象。
 * @param json_data 输入的 JSON 数据。
 * @return 返回解析后的 cJSON 对象，如果解析失败则返回 NULL。
 */
static cJSON *parse_json_data(const char *json_data)
{
	cJSON *json;
	if (!json_data) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "输入的 JSON 数据为空。\n");
		return NULL;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "解析 JSON 数据: %s\n", json_data);
	json = cJSON_Parse(json_data);
	if (!json) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "解析 JSON 数据失败。\n");
		return NULL;
	}

	return json;
}

/**
 * 解析 JSON 数据并返回 flag 字段的值，判断是否为 "call_end"。
 * @param json_data 输入的 JSON 数据。
 * @return 如果 flag 为 "call_end" 返回 true，否则返回 false。
 */
static switch_bool_t get_flag_and_check(const char *json_data)
{
	const char *flag;
	switch_bool_t result;
	cJSON *flag_item;
	cJSON *json = parse_json_data(json_data);
	if (!json) { return SWITCH_FALSE; }

	flag_item = cJSON_GetObjectItem(json, "flag");
	if (!flag_item) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "JSON 数据中缺少 flag 字段。\n");
		cJSON_Delete(json);
		return SWITCH_FALSE;
	}

	flag = cJSON_GetStringValue(flag_item);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "JSON flag 值: %s\n", flag);

	result = strcmp(flag, "call_end") == 0;
	cJSON_Delete(json);
	return result;
}

/**
 * 解析 JSON 数据并返回 tts_file_path 字段的值。
 * @param json_data 输入的 JSON 数据。
 * @return 返回 tts_file_path 字段的值。
 */
static const char *get_tts_file_path(const char *json_data)
{
	cJSON *tts_path_item;
	const char *tts_path;
	char *tts_path_copy;
	cJSON *json = parse_json_data(json_data);
	if (!json) { return NULL; }

	tts_path_item = cJSON_GetObjectItem(json, "tts_file_path");
	if (!tts_path_item) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "JSON 数据中缺少 tts_file_path 字段。\n");
		cJSON_Delete(json);
		return NULL;
	}

	tts_path = cJSON_GetStringValue(tts_path_item);

	tts_path_copy = strdup(tts_path); // 复制字符串

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "JSON tts_path_copy 值: %s\n", tts_path_copy);
	cJSON_Delete(json);

	return tts_path_copy;
}

/**
 * 解析 JSON 数据并返回 iswuhancallin 字段的值。
 * @param json_data 输入的 JSON 数据。
 * @return 如果 iswuhancallin 为 true 返回 true，否则返回 false。
 */
static switch_bool_t get_iswuhancallin(const char *json_data)
{
	cJSON *iswuhancallin_item;
	switch_bool_t result;
	cJSON *json = parse_json_data(json_data);
	if (!json) {
		return SWITCH_FALSE; // 默认返回 false，解析失败或字段不存在
	}

	iswuhancallin_item = cJSON_GetObjectItem(json, "is_wuhancallin");
	if (!iswuhancallin_item) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "is_wuhancallin 字段在 JSON 数据中不存在。\n");
		cJSON_Delete(json);
		return SWITCH_FALSE; // 默认返回 false，字段不存在
	}

	result = cJSON_IsTrue(iswuhancallin_item);

	cJSON_Delete(json);
	return result;
}

static char *wuhancallin_serialize_json(switch_wuhancallin_docker_t *wuhancallin, int callstatus)
{
	cJSON *pJson = NULL;
	char *writebuf = NULL;
	const char *caller_number = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(wuhancallin->session);
	// ===================== 修复1：声明提前到函数顶部（C90要求） =====================
	const char *x_business = NULL;
	const char *nlp_type = NULL;

	// ===================== 修复2：正确获取SIP头 X-Business =====================
	// 正确API：从channel获取SIP头，兼容所有FreeSWITCH版本
	x_business = switch_channel_get_variable(channel, "sip_h_X-Business");
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "获取到 X-Business SIP头: %s\n",
					x_business ? x_business : "空");

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
	cJSON_AddStringToObject(pJson, "uuid", wuhancallin->uuid);
	cJSON_AddStringToObject(pJson, "caller_id_number", caller_number);
	// 把X-Business加入JSON
	cJSON_AddStringToObject(pJson, "x_business", x_business ? x_business : "");
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
 * @param g_wuhancallin 指向 switch_wuhancallin_docker_t 结构体的指针。
 * @return 成功返回 0，失败返回负值。
 */
static int create_client(switch_wuhancallin_docker_t *g_wuhancallin)
{
	struct sockaddr_in SockAddr = {0};
	int ret = -1;

	g_wuhancallin->cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_wuhancallin->cfd < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create socket\n");
		return g_wuhancallin->cfd;
	}

	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = htons(PORT);
	inet_pton(AF_INET, ADDR, &SockAddr.sin_addr.s_addr);

	if (0 > (ret = connect(g_wuhancallin->cfd, (struct sockaddr *)&SockAddr, sizeof(SockAddr)))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, " errorno is %s  \n", strerror(errno));
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "connect server success!!! \n");
	}

	return ret;
}

/**
 * 关闭 CALLIN Docker 函数
 *
 * @param wuhancallin 输入的指向需要初始化的 switch_wuhancallin_docker_t 结构体的指针。
 * @return 返回一个 switch_bool_t 值，表示初始化是否成功。
 */
static switch_bool_t switch_wuhancallin_docker_close(switch_wuhancallin_docker_t *wuhancallin)
{
	int ret = -1;
	switch_core_session_t *session = wuhancallin->session;
	ret = send(wuhancallin->cfd, "call_end", strlen("call_end"), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "when close send socket data fail errno is :%s!!\n", strerror(errno));
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when close send len is :%d!!\n", ret);

	// switch_thread_join(&st, wuhancallin->thread);

	close(wuhancallin->cfd);

	switch_mutex_destroy(wuhancallin->audio_mutex);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
					  "Stopping CALLIN detection for audio stream\n");
	return SWITCH_TRUE;
}

// 封装的函数：用于判断 WAV 文件头部的大小
static long getWavHeaderSize(const char *filename)
{
	long headerSize = 0;
	DataSubchunk dataSubchunk;
	unsigned int fmtChunkSize = 0;
	FmtSubchunk fmtSubchunk;
	RIFFHeader riffHeader;
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "无法打开文件 %s\n", filename);
		return -1;
	}

	// 读取 RIFF 头部
	fread(&riffHeader, sizeof(RIFFHeader), 1, file);

	// 检查 RIFF 头部是否有效
	if (strncmp(riffHeader.chunkID, "RIFF", 4) != 0 || strncmp(riffHeader.format, "WAVE", 4) != 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "不是有效的 WAV 文件\n");
		fclose(file);
		return -1;
	}

	// 读取 fmt subchunk
	fread(&fmtSubchunk, sizeof(FmtSubchunk), 1, file);

	// 计算 fmt 块的大小
	fmtChunkSize = fmtSubchunk.subchunk1Size;

	// 如果 fmt 块大小大于 16，说明是扩展格式，跳过额外的数据
	if (fmtChunkSize > 16) { fseek(file, fmtChunkSize - 16, SEEK_CUR); }

	// 读取接下来的块，寻找 "data" 块
	while (fread(&dataSubchunk, sizeof(DataSubchunk), 1, file)) {
		// 检查是否是 "data" 块
		if (strncmp(dataSubchunk.subchunk2ID, "data", 4) == 0) {
			break;
		} else {
			// 如果不是 "data" 块，跳过这个块的数据
			fseek(file, dataSubchunk.subchunk2Size, SEEK_CUR);
		}
	}

	// 计算头部的总大小（从文件开始到 "data" 块开始）
	headerSize = ftell(file) - sizeof(dataSubchunk.subchunk2Size);

	fclose(file);
	return headerSize;
}

/**
 * 处理接收线程的函数。
 * @param thread 指向 switch_thread_t 结构的指针。
 * @param user_data 用户数据的指针。
 * @return 返回处理后的数据指针。
 */
static void *SWITCH_THREAD_FUNC RecvPthread(switch_thread_t *thread, void *user_data)
{
	long headerSize = 0;
	switch_wuhancallin_docker_t *wuhancallin = (switch_wuhancallin_docker_t *)user_data;
	char readbuf[360] = {0};
	int ret = -1;
	void *dummy;
	const char *tts_path;
	switch_bool_t iswuhancallin;
	switch_channel_t *channel = switch_core_session_get_channel(wuhancallin->session);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "----------------RecvPthread start !!----------------\n");

	while (switch_channel_ready(channel)) {
		ret = recv(wuhancallin->cfd, readbuf, sizeof(readbuf), 0);
		if (ret < 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvPthread: recv() fail errno: %s!!\n",
							  strerror(errno));
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			break;
		} else if (ret > 0) {
			// 将log标志进行重置，每次接收数据后，发送音频流的时候就会打印一条log
			wuhancallin->log_flag = TRUE;

			// 判断当前是否是接收到了模型的wuhancallin信息，表示有人说话了
			iswuhancallin = get_iswuhancallin(readbuf);
			if (!iswuhancallin) {

				switch_mutex_lock(wuhancallin->audio_mutex);
				// 清空 audio_queue
				while (switch_queue_size(wuhancallin->audio_queue) >= 1) {
					// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "需要打断,正在清理audio_queue队列\n");

					if (switch_queue_trypop(wuhancallin->audio_queue, &dummy) != SWITCH_STATUS_SUCCESS) {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "trypop audio_queue 失败\n");
					}
				}
				switch_mutex_unlock(wuhancallin->audio_mutex);

				// 解析 tts_file_path 并读取文件内容
				tts_path = get_tts_file_path(readbuf);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "读取音频数据的文件是%s\n", tts_path);
				if (tts_path && strlen(tts_path) > 0) {
					int fd = open(tts_path, O_RDONLY);
					if (fd) {
						char filebuf[320];
						size_t bytes_read;
						char *buffer_copy = NULL;
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "开始读取音频数据\n");
						switch_mutex_lock(wuhancallin->audio_mutex);

						headerSize = getWavHeaderSize(tts_path);
						if (headerSize != -1) {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "WAV 文件头部大小为：%ld 字节\n",
											  headerSize);
							headerSize = headerSize +ADD_SIZE;
						} else {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
											  "文件不是有效的 WAV 文件或读取失败。\n");
						}

						// 跳过 WAV 文件头
						if (lseek(fd, headerSize, SEEK_SET) < 0) {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "音频文件跳过开头固定字节数失败\n");
							close(fd);
							break;
						}

						while ((bytes_read = read(fd, filebuf, sizeof(filebuf))) > 0) {

							// 为 filebuf 申请一块内存
							buffer_copy = (char *)malloc(sizeof(filebuf));
							if (!buffer_copy) {
								switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "内存分配失败！\n");
								// break;
							}

							// 将数据复制到新分配的内存中
							memcpy(buffer_copy, filebuf, sizeof(filebuf));

							while (switch_queue_trypush(wuhancallin->audio_queue, buffer_copy) != SWITCH_STATUS_SUCCESS) {
								if (wuhancallin->retry_count >= 3) {
									wuhancallin->retry_count = 0;
									break;
								}
								wuhancallin->retry_count++;
								switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "push audio_queue 失败\n");
							}
							memset(filebuf, 0, sizeof(filebuf));
						}
						switch_mutex_unlock(wuhancallin->audio_mutex);
						close(fd);
					} else {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "无法打开文件: %s\n", tts_path);
					}
				}

				switch_mutex_lock(wuhancallin->audio_mutex);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "iscontiue_flag 在线程中上锁\n");
				wuhancallin->iscontiue_flag = TRUE;
				switch_mutex_unlock(wuhancallin->audio_mutex);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "iscontiue_flag 在线程中解锁\n");

				// 判断 flag 是否为 "call_end"
				if (get_flag_and_check(readbuf)) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "线程接收到call_end标志\n");
					break;
				}
			} else {
				// 接收到打断标志停止播放
				switch_mutex_lock(wuhancallin->audio_mutex);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "iscontiue_flag 在线程中上锁\n");
				wuhancallin->iscontiue_flag = FALSE;
				switch_mutex_unlock(wuhancallin->audio_mutex);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "iscontiue_flag 在线程中解锁\n");
				// 判断 flag 是否为 "call_end"
				if (get_flag_and_check(readbuf)) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "线程接收到call_end标志\n");
					wuhancallin->is_playback_end = TRUE;
					break;
				}
			}

		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RecvPthread: socket disconnect!\n");
			//switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			break;
		}
		// 清空操作
		memset(readbuf, 0, sizeof(readbuf));

		if (wuhancallin->audio_pthread_exit) { break; }
	}
	wuhancallin->pthread_exit = TRUE;
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
	switch_wuhancallin_docker_t *wuhancallin = (switch_wuhancallin_docker_t *)user_data;
	switch_channel_t *channel = switch_core_session_get_channel(wuhancallin->session);
	switch_status_t status;
	switch_frame_t *read_frame;
	switch_core_session_t *session = wuhancallin->session;
	int ret = -1;
	void *pop = NULL;
	unsigned int audio_size = 0;

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
		if (!wuhancallin->pthread_exit) {
			ret = send(wuhancallin->cfd, read_frame->data, read_frame->datalen, 0);
			if (ret < 0) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
								  "when talking send socket data fail errno is :%s!!\n", strerror(errno));
				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			} else if (ret > 0) {
				if (wuhancallin->log_flag == TRUE) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
									  "send len is :%d everytime!!\n", ret);
					wuhancallin->log_flag = FALSE;
				}
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "发送的音频流字节数is :%d!!\n",
								  ret);
			}
		}

		switch_mutex_lock(wuhancallin->audio_mutex);
		if (wuhancallin->iscontiue_flag) {
			if (wuhancallin->log_flag == TRUE) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "获取音频队列的开关打开 \n");
			}
			audio_size = switch_queue_size(wuhancallin->audio_queue);
			if (audio_size >= 1) {
				// 播放开始标志
				wuhancallin->is_playback_end = FALSE;
				if (wuhancallin->log_flag == TRUE) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
									  "音频队列的数据大于等于1 %d \n", audio_size);
					wuhancallin->log_flag = FALSE;
				}
				switch_queue_pop(wuhancallin->audio_queue, &pop);
				// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "弹出的数据是%s\n", (char *)pop);

				// 复制pop指向的内容到data
				memcpy(read_frame->data, pop, 320);

				switch_core_session_write_frame(wuhancallin->session, read_frame, SWITCH_IO_FLAG_NONE, 0);
				// switch_core_media_bug_set_write_replace_frame(bug, linear_frame);

				// 将pop清空
				pop = NULL;
			} else {
				ret = send(wuhancallin->cfd, wuhancallin->sendbuf, strlen(wuhancallin->sendbuf), 0);
				if (ret <= 0) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "发送play back end的时候发生错误 :%s!!\n",
									  strerror(errno));
					switch_mutex_unlock(wuhancallin->audio_mutex);
					switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "play back end发送成功\n");
					// 播放结束标志
					wuhancallin->is_playback_end = TRUE;
				}
				wuhancallin->iscontiue_flag = FALSE;
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "音频队列大小为空 \n");
			}
		}
		switch_mutex_unlock(wuhancallin->audio_mutex);

		if (wuhancallin->pthread_exit && wuhancallin->is_playback_end) {
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
	wuhancallin->audio_pthread_exit = TRUE;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "AudioProcessPthread: pthread is over!\n");
	return NULL;
}

/**
 * 初始化 CALLIN Docker 结构体。
 *
 * @param wuhancallin 输入的指向需要初始化的 switch_wuhancallin_docker_t 结构体的指针。
 * @return 返回一个 switch_bool_t 值，表示初始化是否成功。
 */
static switch_bool_t switch_wuhancallin_docker_init(switch_wuhancallin_docker_t *wuhancallin)
{

	int ret = -1;
	char readbuf[256] = {0};
	char *serialize_json = NULL;
	switch_threadattr_t *thd_attr = NULL;
	switch_threadattr_t *thd_farm = NULL;
	switch_core_session_t *session = NULL;
	switch_channel_t *channel = NULL;

	wuhancallin->cfd = -1;
	wuhancallin->log_flag = TRUE;
	wuhancallin->uuid = NULL;
	wuhancallin->pthread_exit = FALSE;
	wuhancallin->iscontiue_flag = FALSE;
	wuhancallin->is_playback_end = FALSE;
	wuhancallin->audio_pthread_exit = FALSE;
	wuhancallin->retry_count = 0;

	session = wuhancallin->session;
	channel = switch_core_session_get_channel(session);

	if (NULL == wuhancallin) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "wuhancallin为NULL");
		return SWITCH_FALSE;
	}

	strcpy(wuhancallin->sendbuf, "playback_end");
	switch_queue_create(&wuhancallin->audio_queue, MAX_AUDIO_QUEUE_LEN, switch_core_session_get_pool(wuhancallin->session));

	// 初始化
	if ((ret = create_client(wuhancallin)) == -1) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "create_client fail\n");
		return SWITCH_FALSE;
	}

	wuhancallin->uuid = switch_core_session_get_uuid(session);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "这通电话的uuid: %s \n", wuhancallin->uuid);

	serialize_json = wuhancallin_serialize_json(wuhancallin, 1);
	if (NULL == serialize_json) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "wuhancallin_serialize_json fail!!\n");
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
						  "wuhancallin_serialize_json success writebuf is %s\n", serialize_json);
	}

	ret = send(wuhancallin->cfd, serialize_json, strlen(serialize_json), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "when init send socket data fail errno is :%s!!\n", strerror(errno));
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when init send len is :%d!!\n", ret);

	ret = recv(wuhancallin->cfd, readbuf, sizeof(readbuf), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "recv()  empty data wuhancallin no catch :%s!!\n", strerror(errno));
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "recv readbuf is %s \n", readbuf);
	}

	// 判断 flag 是否为 "call_end"
	if (get_flag_and_check(readbuf)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "media bug 初始化的时候!!\n");
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
		return SWITCH_TRUE;
	}

	

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
					  "Starting CALLIN detection for audio stream  ");

	wuhancallin->pool = switch_core_session_get_pool(session);

	// 在初始化代码中创建互斥锁
	switch_mutex_init(&wuhancallin->audio_mutex, SWITCH_MUTEX_NESTED, wuhancallin->pool);

	switch_threadattr_create(&thd_attr, wuhancallin->pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&wuhancallin->thread, thd_attr, RecvPthread, wuhancallin, wuhancallin->pool);

	switch_threadattr_create(&thd_farm, wuhancallin->pool);
	switch_threadattr_detach_set(thd_farm, 1);
	switch_threadattr_stacksize_set(thd_farm, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&wuhancallin->audio_thread, thd_farm, AudioProcessPthread, wuhancallin, wuhancallin->pool);

	return SWITCH_TRUE;
}


SWITCH_MODULE_LOAD_FUNCTION(mod_wuhancallin_load)
{
	switch_application_interface_t *app_interface;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_APP(app_interface, "wuhancallin", "Voice activity detection", "Freeswitch's CALLIN", wuhancallin_start_function,
				   "[start|stop]", SAF_NONE);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, " wuhancallin_load successful...\n");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_wuhancallin_shutdown) { return SWITCH_STATUS_SUCCESS; }

SWITCH_STANDARD_APP(wuhancallin_start_function)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_wuhancallin_docker_t *s_wuhancallin = NULL;
	switch_codec_implementation_t imp = {0};
	switch_bool_t ret;

	if (!zstr(data)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "CallIn input parameter %s\n", data);
	}

	if ((s_wuhancallin = (switch_wuhancallin_docker_t *)switch_channel_get_private(channel, CALLIN_PRIVATE))) {
		if (!zstr(data) && !strcasecmp(data, "stop")) {
			switch_channel_set_private(channel, CALLIN_PRIVATE, NULL);
			if (s_wuhancallin->read_bug) {
				switch_core_media_bug_remove(session, &s_wuhancallin->read_bug);
				s_wuhancallin->read_bug = NULL;
				switch_core_session_reset(session, SWITCH_TRUE, SWITCH_TRUE);
			}
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Stopped CALLIN detection\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
							  "Cannot run wuhancallin detection 2 times on the same session!\n");
		}
		return;
	}

	s_wuhancallin = switch_core_session_alloc(session, sizeof(*s_wuhancallin));
	switch_assert(s_wuhancallin);
	memset(s_wuhancallin, 0, sizeof(*s_wuhancallin));
	s_wuhancallin->session = session;

	switch_core_session_raw_read(session);
	switch_core_session_get_read_impl(session, &imp);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Read imp %u %u.\n", imp.samples_per_second,
					  imp.number_of_channels);

	ret = switch_wuhancallin_docker_init(s_wuhancallin);
	if (!ret) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "程序初始化失败，结束通话\n");
		return;
	}

	switch_channel_set_private(channel, CALLIN_PRIVATE, s_wuhancallin);

	while (!s_wuhancallin->audio_pthread_exit) {
    // 必须加这行，让FreeSWITCH处理挂断事件
    switch_ivr_parse_all_events(s_wuhancallin->session);
    switch_sleep(10 * 1000);
}
	ret = switch_wuhancallin_docker_close(s_wuhancallin);
	if (!ret) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "程序初始化失败，结束通话\n");
		return;
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "当前通话任务结束\n");
}
