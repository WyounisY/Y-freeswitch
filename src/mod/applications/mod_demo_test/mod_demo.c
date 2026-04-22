#include <switch.h>

/* Prototypes */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_audio_stream_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_audio_stream_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_audio_stream_load);

/* SWITCH_MODULE_DEFINITION(name, load, shutdown, runtime)
* Defines a switch_loadable_module_function_table_t and a static const char[] modname
 */
SWITCH_MODULE_DEFINITION(mod_audio_stream, mod_audio_stream_load, mod_audio_stream_shutdown, NULL);

// 固定音频文件路径
#define AUDIO_PATH "/tmp/audio_files/"
#define MAX_FILES 100

// 获取目录中所有音频文件
static int get_audio_files(const char *path, char **files, int max_files) {
	switch_dir_t *dir;
	switch_file_t *file;
	int count = 0;
	const char *filename;

	if (switch_dir_open(&dir, path, NULL) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot open directory: %s\n", path);
		return 0;
	}

	while (switch_dir_read_directory(dir, &file) == SWITCH_STATUS_SUCCESS) {
		filename = switch_file_get_name(file);

		// 检查是否为音频文件
		if (switch_stristr(".wav", filename) ||
			switch_stristr(".mp3", filename) ||
			switch_stristr(".ogg", filename) ||
			switch_stristr(".gsm", filename)) {

			if (count < max_files) {
				files[count] = switch_mprintf("%s%s", path, filename);
				count++;
			}
		}
	}

	switch_dir_close(dir);
	return count;
}

SWITCH_STANDARD_APP(audio_stream_app_function)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	char *files[MAX_FILES];
	int file_count = 0;
	int current_file = 0;
	switch_file_handle_t file_handle = {0};
	void *read_buf = NULL;
	switch_size_t read_len = 0;
	switch_frame_t frame = {0};
	switch_codec_t read_codec = {0};
	char *audio_path = AUDIO_PATH;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Starting audio stream application\n");

	// 获取音频文件列表
	file_count = get_audio_files(audio_path, files, MAX_FILES);
	if (file_count == 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No audio files found in %s\n", audio_path);
		return SWITCH_STATUS_FALSE;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Found %d audio files\n", file_count);

	// 初始化读取codec
	if (switch_core_codec_init(&read_codec,
							   "L16",
							   NULL,
							   NULL,
							   8000,        // 8k采样率
							   20,          // 20ms帧大小
							   1,           // 单声道
							   SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE,
							   NULL, NULL) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot initialize read codec\n");
		goto end;
	}

	// 分配读取缓冲区
	read_buf = switch_core_session_alloc(session, SWITCH_RECOMMENDED_BUFFER_SIZE);
	frame.data = read_buf;
	frame.buflen = SWITCH_RECOMMENDED_BUFFER_SIZE;

	// 主循环 - 播放所有音频文件
	while (switch_channel_ready(channel)) {
		// 打开音频文件
		memset(&file_handle, 0, sizeof(file_handle));
		file_handle.channels = 1;
		file_handle.samples_per_second = 8000;  // 8k采样率

		if (switch_core_file_open(&file_handle,
								  files[current_file],
								  file_handle.channels,
								  file_handle.samples_per_second,
								  SWITCH_FILE_FLAG_READ,
								  NULL) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
							  "Cannot open file: %s\n", files[current_file]);
			current_file = (current_file + 1) % file_count; // 移到下一个文件
			switch_yield(100000); // 等待100ms
			continue;
		}

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
						  "Playing file: %s\n", files[current_file]);

		// 播放当前文件
		while (switch_channel_ready(channel)) {
			read_len = SWITCH_RECOMMENDED_BUFFER_SIZE;

			if (switch_core_file_read(&file_handle, read_buf, &read_len) != SWITCH_STATUS_SUCCESS) {
				break; // 文件读取完毕
			}

			if (read_len == 0) {
				break; // 没有更多数据
			}

			frame.data = read_buf;
			frame.datalen = read_len;
			frame.samples = read_len / 2; // 假设16位音频
			frame.codec = &read_codec;
			frame.rate = file_handle.samples_per_second;

			// 发送到通道
			if (switch_core_session_write_frame(session, &frame, SWITCH_IO_FLAG_NONE) != SWITCH_STATUS_SUCCESS) {
				break;
			}

			// 简单的延时控制
			switch_yield(10000); // 10ms
		}

		// 关闭当前文件
		switch_core_file_close(&file_handle);

		// 移到下一个文件（循环播放）
		current_file = (current_file + 1) % file_count;

		// 短暂暂停后继续播放下一个文件
		switch_yield(100000); // 100ms暂停
	}

end:
	// 清理资源
	for (int i = 0; i < file_count; i++) {
		switch_safe_free(files[i]);
	}

	if (read_buf) {
		switch_core_session_free(session, &read_buf);
	}

	if (read_codec.codec_interface) {
		switch_core_codec_destroy(&read_codec);
	}

	return SWITCH_STATUS_SUCCESS;
}

/* Macro expands to: switch_status_t mod_audio_stream_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool) */
SWITCH_MODULE_LOAD_FUNCTION(mod_audio_stream_load)
{
	switch_application_interface_t *app_interface;

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_APP(app_interface,
				   "audio_stream",
				   "Stream audio files from directory",
				   "Continuously play audio files from fixed directory",
				   audio_stream_app_function,
				   NULL,
				   SMD_ASL_UNREG);

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_audio_stream_shutdown)
{
	return SWITCH_STATUS_SUCCESS;
}