#include <switch.h>
#include <sys/time.h>

#define ROBOT_PRIVATE "_robot_" // robot模块哈希key值
#define BUFFER_SIZE 320

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_robot_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_robot_load);
SWITCH_MODULE_DEFINITION(mod_robot, mod_robot_load, mod_robot_shutdown, NULL);
SWITCH_STANDARD_APP(robot_start_function);

typedef struct {
	switch_core_session_t *session;
	FILE *file;
} robot_data_t;

static switch_bool_t robot_audio_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	robot_data_t *robot_data = (robot_data_t *)user_data;
	FILE *file = robot_data->file;
	char buffer[BUFFER_SIZE];
	size_t bytesRead;

	switch (type) {
	case SWITCH_ABC_TYPE_INIT:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "初始化 !!\n");
		// 打开文件
		file = fopen("/usr/local/freeswitch/sounds/en/us/callie/wangyuan_111.wav", "rb");
		if (file == NULL) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "无法打开文件\n");
			return SWITCH_FALSE;
		}
		robot_data->file = file;
		break;
	case SWITCH_ABC_TYPE_CLOSE:
		if (file != NULL) {
			fclose(file);
			robot_data->file = NULL;
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "通话关闭处理程序\n");
		break;
	case SWITCH_ABC_TYPE_READ_REPLACE: {
		switch_frame_t *linear_frame;
		linear_frame = switch_core_media_bug_get_read_replace_frame(bug);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "读取用户声音帧 长度是%d\n", linear_frame->datalen);
		if (file && (bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "读取了 %zu 字节\n", bytesRead);
			memcpy(linear_frame->data, buffer, bytesRead);
			linear_frame->datalen = bytesRead;
		}
		if (ferror(file)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "读取文件时出错\n");
			fclose(file);
			robot_data->file = NULL;
			return SWITCH_FALSE;
		}
		

		switch_core_session_write_frame(robot_data->session, linear_frame, SWITCH_IO_FLAG_NONE, 0);
		break;
	}
	default:
		break;
	}

	return SWITCH_TRUE;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_robot_load)
{
	switch_application_interface_t *app_interface;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_APP(app_interface, "robot", "Voice activity detection", "Freeswitch's ROBOT", robot_start_function,
				   "[start|stop]", SAF_NONE);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, " robot_load successful...\n");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_robot_shutdown) { return SWITCH_STATUS_SUCCESS; }

SWITCH_STANDARD_APP(robot_start_function)
{
	switch_status_t status;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_codec_implementation_t imp = {0};
	switch_media_bug_t *bug;
	robot_data_t *robot_data;
	int flags = 0;

	if (!zstr(data)) { switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "ROBOT input parameter %s\n", data); }

	if ((bug = (switch_media_bug_t *)switch_channel_get_private(channel, ROBOT_PRIVATE))) {
		if (!zstr(data) && !strcasecmp(data, "stop")) {
			switch_channel_set_private(channel, ROBOT_PRIVATE, NULL);
			if (bug) {
				switch_core_media_bug_remove(session, &bug);
				bug = NULL;
				switch_core_session_reset(session, SWITCH_TRUE, SWITCH_TRUE);
			}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Stopped ROBOT detection\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Cannot run robot detection 2 times on the same session!\n");
		}
		return;
	}

	switch_core_session_raw_read(session);
	switch_core_session_get_read_impl(session, &imp);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Read imp %u %u.\n", imp.samples_per_second,
					  imp.number_of_channels);

	robot_data = (robot_data_t *)switch_core_session_alloc(session, sizeof(robot_data_t));
	robot_data->file = NULL;

	robot_data->session = session;
	flags = SMBF_READ_REPLACE | SMBF_ANSWER_REQ;
	status = switch_core_media_bug_add(session, "robot_read", NULL, robot_audio_callback, robot_data, 0, flags, &bug);

	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to attach robot to media stream!\n");
		return;
	}

	switch_channel_set_private(channel, ROBOT_PRIVATE, bug);
}
