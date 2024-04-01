#include <switch.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_uuid_playback_continue_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_uuid_playback_continue_shutdown);

SWITCH_MODULE_DEFINITION(mod_uuid_playback_continue, mod_uuid_playback_continue_load, mod_uuid_playback_continue_shutdown, NULL);

static switch_status_t uuid_to_playback_continue(switch_core_session_t *psession, const char *filepath)
{

    switch_status_t status = SWITCH_STATUS_SUCCESS;


    status = switch_ivr_play_file(psession, NULL, filepath,NULL);

    switch (status) {
    case SWITCH_STATUS_SUCCESS:
        break;
    case SWITCH_STATUS_BREAK:
        break;
    case SWITCH_STATUS_NOTFOUND:
        break;
    default:
        break;
    }
    return status;

}

SWITCH_STANDARD_API(uuid_playback_continue)
{
    char *mycmd = NULL, *argv[2] = { 0 };
    const char *uuid;
    const char *filepath;
    int argc = 0;
    switch_status_t status;
    switch_core_session_t *psession = NULL;

    if (!zstr(cmd) && (mycmd = strdup(cmd))) {
    	argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
    }
    if (zstr(cmd) || argc < 2) {
        stream->write_function(stream, "-USAGE: uuid_playback_continue <uuid> <filepath>\n");
        return SWITCH_STATUS_SUCCESS;
    }

    uuid = argv[0];
    filepath = argv[1];

     if (!(psession = switch_core_session_locate(uuid))) {
        stream->write_function(stream, "-ERR No such channel!\n");
        return SWITCH_STATUS_SUCCESS;
     }

    status = uuid_to_playback_continue(psession, filepath);

    if (status == SWITCH_STATUS_SUCCESS) {
        stream->write_function(stream, "+OK\n");
    } else {
        stream->write_function(stream, "-ERR\n");
    }
    switch_core_session_rwunlock(psession);
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_uuid_playback_continue_load)
{
    switch_api_interface_t *api_interface;

    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    SWITCH_ADD_API(api_interface, "uuid_playback_continue", "Playback API Function", uuid_playback_continue, "Playback API Function");
    switch_console_set_complete("add uuid_playback_continue <uuid> <filepath>");

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Playback API module loaded\n");

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_uuid_playback_continue_shutdown)
{
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Playback API module unloaded\n");

    return SWITCH_STATUS_SUCCESS;
}