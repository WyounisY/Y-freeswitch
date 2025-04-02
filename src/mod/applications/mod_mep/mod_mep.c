#include <switch.h>
#include <sys/time.h>

#define MEP_PRIVATE "_mep_"		  // mep模块哈希key值
//#define MEP_XML_CONFIG "mep.conf" // 配置文件名
#define MOUDLE_NLP_TYPE "mep" // 配置文件名
// #define MEP_EVENT_SUBCLASS "mep::detection" //mep自定义事件名
#define PORT_READ 8010	 // 目标地址端口号处理读取 人工处理的音频流
#define PORT_WRITE 8020	 // 目标地址端口号处理写入 商家的音频流
#define ADDR "127.0.0.1" // 目标地址IP

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_mep_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_mep_load);
SWITCH_MODULE_DEFINITION(mod_mep, mod_mep_load, mod_mep_shutdown, NULL);
SWITCH_STANDARD_APP(mep_start_function);

typedef struct {
	switch_core_session_t *session;
	switch_codec_implementation_t *read_impl;
	switch_media_bug_t *rw_bug;
	switch_memory_pool_t *pool;

	int channels;
	int sample_rate;
	int read_fd;
	int write_fd;
	int cfd_read;
	int cfd_write;
	// 这条腿的uuid
	char *uuid;
	switch_bool_t log_flag;
} switch_mep_docker_t;

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
 * 创建客户端并连接到服务器。
 * @param g_mep 指向 switch_mep_docker_t 结构体的指针。
 * @return 成功返回 0，失败返回负值。
 */
static int create_client(switch_mep_docker_t *g_mep)
{
	struct sockaddr_in SockAddrRead = {0};
	struct sockaddr_in SockAddrWrite = {0};
	int ret = -1;

	g_mep->cfd_read = socket(AF_INET, SOCK_STREAM, 0);
	if (g_mep->cfd_read < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create socket\n");
		return g_mep->cfd_read;
	}

	SockAddrRead.sin_family = AF_INET;
	SockAddrRead.sin_port = htons(PORT_READ);
	inet_pton(AF_INET, ADDR, &SockAddrRead.sin_addr.s_addr);

	if (0 > (ret = connect(g_mep->cfd_read, (struct sockaddr *)&SockAddrRead, sizeof(SockAddrRead)))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, " errorno is %s  \n", strerror(errno));
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "connect server success!!! \n");
	}

	g_mep->cfd_write = socket(AF_INET, SOCK_STREAM, 0);
	if (g_mep->cfd_write < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create socket\n");
		return g_mep->cfd_write;
	}

	SockAddrWrite.sin_family = AF_INET;
	SockAddrWrite.sin_port = htons(PORT_WRITE);
	inet_pton(AF_INET, ADDR, &SockAddrWrite.sin_addr.s_addr);

	if (0 > (ret = connect(g_mep->cfd_write, (struct sockaddr *)&SockAddrWrite, sizeof(SockAddrWrite)))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, " errorno is %s  \n", strerror(errno));
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "connect server success!!! \n");
	}

	return ret;
}

/**
 * 序列化呼叫信息为JSON字符串
 * 
 * @param mep 呼叫信息结构体指针
 * @param callstatus 呼叫状态，1表示呼叫开始，其他值表示呼叫结束
 * @return 返回序列化的JSON字符串，若失败则返回NULL
 * 
 * 此函数根据传入的呼叫信息和状态，生成相应的JSON字符串，用于后续的处理或传输
 * 它首先获取呼叫相关的数据，如nlp_type，然后创建一个JSON对象，添加相关数据，
 * 最后返回这个JSON对象的字符串表示
 */
static char *mep_serialize_json(switch_mep_docker_t *mep)
{
    cJSON *pJson = NULL;
    char *writebuf = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(mep->session);
	const char *call_id = switch_channel_get_variable(channel, "call_id");
	if (!call_id) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "call_id变量不存在 !! : %s \n", call_id);
		return NULL;
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "call_id变量存在 !! : %s \n", call_id);
	}
    // 参数校验
    if (NULL == mep) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                         "Invalid input parameters: mep is null\n");
        return NULL;
    }

    // 创建JSON对象
    pJson = cJSON_CreateObject();
    if (NULL == pJson) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Failed to create JSON object for uuid=%s\n", mep->uuid);
        return NULL;
    }

    // 添加数据到JSON对象
    if (cJSON_AddStringToObject(pJson, "flag", "call_start") == NULL ||
        cJSON_AddStringToObject(pJson, "uuid", mep->uuid) == NULL ||
        cJSON_AddStringToObject(pJson, "nlp_type", MOUDLE_NLP_TYPE) == NULL ||
		cJSON_AddStringToObject(pJson, "call_id", call_id) == NULL ||
        cJSON_AddStringToObject(pJson, "asr_type", "stream") == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Failed to add data to JSON object for uuid=%s\n", mep->uuid);
        goto cleanup;
    }

    // 打印JSON对象为字符串
    writebuf = cJSON_PrintUnformatted(pJson);
    if (NULL == writebuf) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Failed to print JSON object for uuid=%s\n", mep->uuid);
        goto cleanup;
    }

    // 正常情况下释放JSON对象
    cJSON_Delete(pJson);
    return writebuf;

cleanup:
    // 错误处理：释放JSON对象
    if (pJson) {
        cJSON_Delete(pJson);
    }
    return NULL;
}

/**
 * 关闭 mep Docker 函数
 *
 * @param mep 输入的指向需要初始化的 switch_mep_docker_t 结构体的指针。
 * @return 返回一个 switch_bool_t 值，表示初始化是否成功。
 */
static switch_bool_t switch_mep_docker_close(switch_mep_docker_t *mep)
{
	int ret = -1;
	switch_core_session_t *session = mep->session;
	ret = send(mep->cfd_read, "call_end", strlen("call_end"), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "when close send socket data fail errno is :%s!!\n", strerror(errno));
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when cfd_read close send len is :%d!!\n", ret);
	ret = send(mep->cfd_write, "call_end", strlen("call_end"), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "when close send socket data fail errno is :%s!!\n", strerror(errno));
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when cfd_write close send len is :%d!!\n", ret);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,"Stopping MEP detection for audio stream\n");
	return SWITCH_TRUE;
}

/**
 * 解析 JSON 数据并获取 'flag' 字段的值进行检查。
 * 
 * @param json_data 包含 JSON 格式数据的字符串。
 * @return SWITCH_TRUE 如果 'flag' 字段的值为 'call_end'，否则返回 SWITCH_FALSE。
 */
static switch_bool_t get_flag_and_check(const char *json_data)
{
    // 初始化 flag 变量为 NULL
    const char *flag = NULL;
    // 初始化 result 变量为 SWITCH_FALSE
    switch_bool_t result = SWITCH_FALSE;
    // 初始化 flag_item 变量为 NULL
    cJSON *flag_item = NULL;
    // 解析 JSON 数据
    cJSON *json = parse_json_data(json_data);

    // 检查 JSON 数据是否解析成功
    if (!json) {
        // 如果解析失败，记录错误日志并返回 SWITCH_FALSE
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "JSON 数据解析失败: 输入数据可能无效。\n");
        return SWITCH_FALSE;
    }

    // 获取 'flag' 字段的 cJSON 对象
    flag_item = cJSON_GetObjectItem(json, "flag");
    // 检查 'flag' 字段是否存在且为字符串类型
    if (!flag_item || !cJSON_IsString(flag_item)) {
        // 如果 'flag' 字段缺失或格式错误，记录错误日志并跳转到 cleanup 标签
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "JSON 数据中缺少或格式错误的 flag 字段。\n");
        goto cleanup;
    }

    // 获取 'flag' 字段的字符串值
    flag = cJSON_GetStringValue(flag_item);
    // 检查 'flag' 字段的值是否为空
    if (!flag) {
        // 如果 'flag' 字段的值为空，记录错误日志并跳转到 cleanup 标签
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "JSON 数据中 flag 字段为空。\n");
        goto cleanup;
    }

    // 记录 'flag' 字段的值
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "JSON flag 值: %s\n", flag);

    // 检查 'flag' 字段的值是否为 'call_end'
    if (strcmp(flag, "call_end") == 0) {
        // 如果 'flag' 字段的值为 'call_end'，将 result 设置为 SWITCH_TRUE
        result = SWITCH_TRUE;
    }

cleanup:
    // 释放 JSON 对象占用的内存
    if (json) {
        cJSON_Delete(json);
    }
    // 返回检查结果
    return result;
}

static switch_bool_t switch_mep_docker_init(switch_mep_docker_t *mep)
{
	switch_core_session_t *session = NULL;
	switch_channel_t *channel = NULL;
	char readbuf[256] = {0};
	int ret = -1;
	char *serialize_json = NULL;

	if (NULL == mep) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mep为NULL");
		return SWITCH_FALSE;
	}

	mep->read_fd = -1;
	mep->write_fd = -1;
	mep->cfd_read = -1;
	mep->cfd_write = -1;
	mep->uuid = NULL;
	mep->log_flag = TRUE;

	session = mep->session;
	channel = switch_core_session_get_channel(session);

	// 创建socket连接
	if ((ret = create_client(mep)) == -1) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "create_client fail\n");
		return SWITCH_FALSE;
	}

	mep->uuid = switch_core_session_get_uuid(session);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "这通电话的uuid: %s \n", mep->uuid);

	serialize_json = mep_serialize_json(mep);
	if (NULL == serialize_json) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "mep_serialize_json fail!!\n");
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
						  "mep_serialize_json success writebuf is %s\n", serialize_json);
	}

	ret = send(mep->cfd_read, serialize_json, strlen(serialize_json), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "when init send socket data fail errno is :%s!!\n", strerror(errno));
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "when init send len is :%d!!\n", ret);

	ret = recv(mep->cfd_read, readbuf, sizeof(readbuf), 0);
	if (ret <= 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "recv()  empty data mep no catch :%s!!\n", strerror(errno));
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

	return SWITCH_TRUE;
}

static switch_bool_t mep_audio_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	switch_mep_docker_t *mep = (switch_mep_docker_t *)user_data;
	switch_core_session_t *session = mep->session;
	switch_channel_t *channel = switch_core_session_get_channel(mep->session);
	// switch_channel_t *channel = switch_core_session_get_channel(session);
	//char write_filename[256], read_filename[256];
	//ssize_t written = -1;
	int ret = -1;

	switch (type) {
	case SWITCH_ABC_TYPE_INIT:

		mep->uuid = switch_core_session_get_uuid(session);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "   uuid %s \n", mep->uuid);

		// 创建文件路径
		/*snprintf(write_filename, sizeof(write_filename), "/usr/local/freeswitch/recordings/%s_write.raw", mep->uuid);
		snprintf(read_filename, sizeof(read_filename), "/usr/local/freeswitch/recordings/%s_read.raw", mep->uuid);*/

		// 使用 open 替代 fopen
		/*mep->write_fd = open(write_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		mep->read_fd = open(read_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (mep->write_fd == -1 || mep->read_fd == -1) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
							  "Failed to open audio files for writing\n");
			if (mep->write_fd != -1) close(mep->write_fd);
			if (mep->read_fd != -1) close(mep->read_fd);
			return SWITCH_FALSE;
		}*/

		break;
	case SWITCH_ABC_TYPE_CLOSE:

		switch_core_media_bug_flush(bug);
		ret = switch_mep_docker_close(mep);
		if (!ret) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "程序初始化失败，结束通话\n");
		}
		// 关闭文件描述符
	/*	if (mep->write_fd != -1) {
			close(mep->write_fd);
			mep->write_fd = -1;
		}
		if (mep->read_fd != -1) {
			close(mep->read_fd);
			mep->read_fd = -1;
		}
*/	// 关闭socket
		if (mep->cfd_read != -1) {
			close(mep->cfd_read);
			mep->cfd_read = -1;
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Closed read socket\n");
		}
		if (mep->cfd_write != -1) {
			close(mep->cfd_write);
			mep->cfd_write = -1;
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Closed write socket\n");
		}
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "Stopping MEP detection for audio stream\n");
		break;

	case SWITCH_ABC_TYPE_WRITE_REPLACE: {
		switch_frame_t *write_frame = switch_core_media_bug_get_write_replace_frame(bug);
		if (write_frame) {
			ret = send(mep->cfd_write, write_frame->data, write_frame->datalen, 0);
			if (ret < 0) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
								  "Failed to send write frame to socket, errno: %s\n", strerror(errno));
				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
				return SWITCH_FALSE;
			} else if (ret == write_frame->datalen) {
				if (mep->log_flag == TRUE) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
									  "Sent %u bytes to write socket (timestamp: %u)\n", write_frame->datalen,
									  write_frame->timestamp);
					mep->log_flag = FALSE;
				}
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
								  "Sent partial data to write socket: %d/%u bytes\n", ret, write_frame->datalen);
			}
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
							  "Failed to get write frame from media bug\n");
			return SWITCH_FALSE;
		}
			/*switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Frame: codec=%s, datalen=%d, rate=%d,
			   channels=%d\n", write_frame->codec->implementation->iananame, write_frame->datalen, write_frame->rate,
							  write_frame->channels);*/

			/*written = write(mep->write_fd, write_frame->data, write_frame->datalen);

			if (written != write_frame->datalen) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
								  "Failed to write all data to write file (%zd/%u)\n", written, write_frame->datalen);
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
								  "Wrote %u bytes to write file (timestamp: %u)\n", write_frame->datalen,
								  write_frame->timestamp);
			}*/

	} break;

	case SWITCH_ABC_TYPE_READ_REPLACE: {
		switch_frame_t *read_frame = switch_core_media_bug_get_read_replace_frame(bug);
		if (read_frame) {
			ret = send(mep->cfd_read, read_frame->data, read_frame->datalen, 0);
			if (ret < 0) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
								  "Failed to send read frame to socket, errno: %s\n", strerror(errno));
				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
				return SWITCH_FALSE;
			} else if (ret == read_frame->datalen) {
				if (mep->log_flag == TRUE) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
									  "Sent %u bytes to read socket (timestamp: %u)\n", read_frame->datalen,
									  read_frame->timestamp);
				}
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
								  "Sent partial data to read socket: %d/%u bytes\n", ret, read_frame->datalen);
			}
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
							  "Failed to get read frame from media bug\n");
			return SWITCH_FALSE;
		}
		/*switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Frame: codec=%s, datalen=%d, rate=%d, channels=%d\n",
						  read_frame->codec->implementation->iananame, read_frame->datalen, read_frame->rate,
						  read_frame->channels);*/
		/*written = write(mep->read_fd, read_frame->data, read_frame->datalen);

		if (written != read_frame->datalen) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
							  "Failed to write all data to read file (%zd/%u)\n", written, read_frame->datalen);
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
							  "Wrote %u bytes to read file (timestamp: %u)\n", read_frame->datalen,
							  read_frame->timestamp);
		}*/

	} break;
	default:
		break;
	}

	return SWITCH_TRUE;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_mep_load)
{
	switch_application_interface_t *app_interface;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_APP(app_interface, "mep", "media bug eavesdrop process", "Freeswitch's MEP", mep_start_function,
				   "[start|stop]", SAF_NONE);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, " mep_load successful...\n");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_mep_shutdown) { return SWITCH_STATUS_SUCCESS; }

SWITCH_STANDARD_APP(mep_start_function)
{
	switch_status_t status;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_mep_docker_t *s_mep = NULL;
	switch_codec_implementation_t imp = {0};

	if (!zstr(data)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "MEP input parameter %s\n", data);
	}

	if ((s_mep = (switch_mep_docker_t *)switch_channel_get_private(channel, MEP_PRIVATE))) {
		if (!zstr(data) && !strcasecmp(data, "stop")) {
			switch_channel_set_private(channel, MEP_PRIVATE, NULL);
			if (s_mep->rw_bug) {
				switch_core_media_bug_remove(session, &s_mep->rw_bug);
				s_mep->rw_bug = NULL;
				switch_core_session_reset(session, SWITCH_TRUE, SWITCH_TRUE);
			}
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Stopped MEP detection\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
							  "Cannot run mep detection 2 times on the same session!\n");
		}
		return;
	}

	s_mep = switch_core_session_alloc(session, sizeof(*s_mep));
	switch_assert(s_mep);
	memset(s_mep, 0, sizeof(*s_mep));
	s_mep->session = session;

	switch_core_session_raw_read(session);
	switch_core_session_get_read_impl(session, &imp);
	// 打印读取实现的详细信息
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
					  "Read imp: codec_type=%u, ianacode=%u, iananame=%s, fmtp=%s, samples_per_second=%u, "
					  "actual_samples_per_second=%u, bits_per_second=%d, microseconds_per_packet=%d, "
					  "samples_per_packet=%u, decoded_bytes_per_packet=%u, encoded_bytes_per_packet=%u, "
					  "number_of_channels=%u, codec_frames_per_packet=%d, codec_id=%u, impl_id=%u, modname=%s\n",
					  imp.codec_type, imp.ianacode, imp.iananame ? imp.iananame : "NULL", imp.fmtp ? imp.fmtp : "NULL",
					  imp.samples_per_second, imp.actual_samples_per_second, imp.bits_per_second,
					  imp.microseconds_per_packet, imp.samples_per_packet, imp.decoded_bytes_per_packet,
					  imp.encoded_bytes_per_packet, imp.number_of_channels, imp.codec_frames_per_packet, imp.codec_id,
					  imp.impl_id, imp.modname ? imp.modname : "NULL");
	s_mep->sample_rate = imp.samples_per_second ? imp.samples_per_second : 8000;
	s_mep->channels = imp.number_of_channels;

	// just for fmep set!
	switch_mep_docker_init(s_mep);

	status = switch_core_media_bug_add(session, "mep read and write", NULL, mep_audio_callback, s_mep, 0,
									   SMBF_WRITE_REPLACE | SMBF_READ_REPLACE, &s_mep->rw_bug);

	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
						  "Failed to attach mep to media stream!\n");
		return;
	}

	switch_channel_set_private(channel, MEP_PRIVATE, s_mep);
}