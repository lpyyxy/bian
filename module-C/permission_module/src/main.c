//
// Created by lpyyxy on 2022/3/7.
//

#include "main.h"

void initialize_decl_cond();
bool is_permission(long long session_id, Details details);
int main(void)
{
    Config* config = load_config("config.cfg");
    if (!initialize(hash("permission_module"),
        find_config(config, "address"),
        find_config(config, "private_key"))) {
        return 0;
    }
    //初始化数据库
    initialize_decl_cond();
    init_store_data("PermissionStoreData", permission_store_data_decl);
    void block_monitor(BaseEventID base_event_id, bool (*message_handle)(long long session_id, Details details));
}

void initialize_decl_cond() {
    Decl* UID = normal_declaration("UID", LONG);
    Decl* group_id = normal_declaration("group_id", BYTE);
    group_id->is_dynamic_array = true;
    Decl* is_success = normal_declaration("is_success", BOOLEAN);
    is_success->Array_size = 6;
    Decl* other_id = normal_declaration("other_id", LONG);
    other_id->is_dynamic_array = true;
    permission_store_data_decl = object_declaration("PermissionStoreData", 4, UID, group_id, is_success, other_id);

    Cond message_submission_2 = {
            .operate = NONE,
            .target = "type",
            .where_operate = EQUAL,
            .type = OBJ,
            .value = "submission",
            .successor = NULL
    };
    Cond message_submission_1 = {
            .operate = AND,
            .target = "id",
            .where_operate = EQUAL,
            .type = OBJ,
            .value = "",
            .successor = &message_submission_2
    };
    message_submission_cond = &message_submission_1;

    Cond message_initialize_2 = {
            .operate = NONE,
            .target = "type",
            .where_operate = EQUAL,
            .type = OBJ,
            .value = "initialize",
            .successor = NULL
    };
    Cond message_initialize_1 = {
            .operate = AND,
            .target = "id",
            .where_operate = EQUAL,
            .type = OBJ,
            .value = "",
            .successor = &message_initialize_2
    };
    message_initialize_cond = &message_initialize_1;
}

bool is_permission(long long session_id, Details details) {
    SessionIdObtainUIdSrcData sessionIdObtainUIdSrcData = {
            .session_id = session_id
    };
    Cond store_data_eigenvalues = {
            .operate = NONE,
            .target = "UID",
            .where_operate = EQUAL,
            .type = LONG,
            .value = (char*)&(((SessionIdObtainUId*)get_module_data(hash("user_module"),
                                                                      "SessionIdObtainUID",
                                                                      &sessionIdObtainUIdSrcData,
                                                                      sizeof(sessionIdObtainUIdSrcData)))
                                                                              ->u_Id),
      .successor = NULL
    };

}
