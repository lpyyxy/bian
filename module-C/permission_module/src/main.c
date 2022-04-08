//
// Created by lpyyxy on 2022/3/7.
//

#include "main.h"

int main(void)
{
    //初始化
    Config* config = load_config("config.cfg");
    if (!initialize(string_hash("permission_module"),   
        find_config(config, "address"),
        find_config(config, "private_key"))) {
        return 0;
    }
    initialize_decl_cond();
    //初始化数据库
    init_store_data("PermissionStoreData", permission_store_data_decl);
    block_monitor(base_event_id, message_accept);
    block_monitor(base_event_id, message_sent);
    block_monitor(base_event_id, store_add);
    block_monitor(base_event_id, store_get);
    block_monitor(base_event_id, store_remove);
    block_monitor(base_event_id, other_data);
    getusergroup_permission *teachergroup_data= (getusergroup_permission*)get_config("Teacher", permission_store_data_decl);
    getusergroup_permission *subjectgroup_data = (getusergroup_permission*)get_config("Subject", permission_store_data_decl);
    getusergroup_permission *administrator_data = (getusergroup_permission*)get_config("Administrator", permission_store_data_decl);
    return 0;
} 
Permission* change_string(String *str) {
    int k = 0, j = 0, l=0;
    Permission* temp_permission;
    for (int i = 0; i < str->value_length; i++) {
        if (str->value[i] != '/') {
            k++;
        }
        else {
            temp_permission->permission[j++] = hash_array(str->value[l], k);
            k = 0;
            l += k;

        }
    }
        temp_permission->permission_size = j;
        return temp_permission;
}
bool have_permission(Permission permission, BaseEventID baseEventId, Details details) {
    long long event_1;
    long long event_2;
    switch (baseEventId) {
    case MESSAGE_ACCEPT:
    case MESSAGE_SEND:
        event_1 = hash_string("message");
        break;
    case STORE_DATA_ADD:
    case STORE_DATA_REMOVE:
    case STORE_DATA_UPDATE:
    case STORE_DATA_GET:
        event_1 = hash_string("store_data");
        break;
    default:
        return false;
    }
    switch (baseEventId) {
    case MESSAGE_ACCEPT:
        event_2 = hash_string("accept");
        break;
    case MESSAGE_SEND:
        event_2 = hash_string("send");
        break;
    case STORE_DATA_ADD:
        event_2 = hash_string("add");
        break;
    case STORE_DATA_REMOVE:
        event_2 = hash_string("remove");
        break;
    case STORE_DATA_UPDATE:
        event_2 = hash_string("update");
        break;
    case STORE_DATA_GET:
        event_2 = hash_string("get");
        break;
    default:
        return false;
    }
    if (permission.permission[0] != event_1 &&
        (permission.permission_size > 1 && permission.permission[1] != event_2)) {
        return false;
    }
    switch (baseEventId) {
    case MESSAGE_ACCEPT:
        if ((permission.permission_size > 2 && permission.permission[2] != hash_string(details.messageAcceptDetails.id)) &&
            (permission.permission_size > 3 && permission.permission[3] != hash_string(details.messageAcceptDetails.type))) {
            return false;
        }
        return true;
    case MESSAGE_SEND:
        if ((permission.permission_size > 2 && permission.permission[2] != hash_string(details.messageSendDetails.id)) &&
            (permission.permission_size > 3 && permission.permission[3] != hash_string(details.messageSendDetails.type))){
            return false;
    }
        return true;
        break;
    case STORE_DATA_ADD: 
        if ((permission.permission_size > 2 && permission.permission[2] != hash_string(details.storeDataAddDetails.store_data_table_name)) &&
            (permission.permission_size > 3 && permission.permission[3] != hash_string(details.storeDataAddDetails.row))) {
            return false;
        }
        return true;
        break;
    case STORE_DATA_REMOVE:
        if ((permission.permission_size > 2 && permission.permission[2] != hash_string(details.storeDataRemoveDetails.store_data_table_name)) &&
            (permission.permission_size > 3 && permission.permission[3] != hash_string(details.storeDataRemoveDetails.row))) {
            return false;
        }
        return true;
        break;
    case STORE_DATA_UPDATE:
        if ((permission.permission_size > 2 && permission.permission[2] != hash_string(details.storeDataUpdateDetails.store_data_table_name)) &&
            (permission.permission_size > 3 && permission.permission[3] != hash_string(details.storeDataUpdateDetails.row))) {
            return false;
        }
        return true;
        break;
    case STORE_DATA_GET:
        if ((permission.permission_size > 2 && permission.permission[2] != hash_string(details.storeDataGetDetails.store_data_table_name)) &&
            (permission.permission_size > 3 && permission.permission[3] != hash_string(details.storeDataGetDetails.row))) {
            return false;
        }
        return true;
        break;
    default:
        return false;
    }
}
//消息接受权限
bool message_accept(long long session_id,Details details) {
    int j = 0;
    SessionIdObtainUIdSrcData sessionIdObtainUIdSrcData = {
           .session_id = session_id
    };
    Cond store_data_eigenvalues = {
            .operate = NONE,
            .target = "UID",
            .where_operate = EQUAL,
            .type = LONG,
            .value = (char*)&(((SessionIdObtainUId*)get_module_data(string_hash("user_module"),
                                                                      "SessionIdObtainUID",
                                                                      &sessionIdObtainUIdSrcData,
                                                                      sizeof(sessionIdObtainUIdSrcData)))
                                                                              ->UID),
            .successor = NULL
    };
     MessageAccept* accept_permission=(get_store_data("PermissionStoreData",&store_data_eigenvalues,user_permission_accept_decl,sizeof(MessageAccept)).data[0]);
     j = accept_permission->messageAccept_size;
    for (int i = 0; i < accept_permission->messageAccept_size; i++) {
        if (have_permission(accept_permission->messageAccept[i], message_accept, details)) {
            return true;
        }
    }
    return false;
}
//消息发送权限
bool message_send(long long session_id, Details details) {
    SessionIdObtainUIdSrcData sessionIdObtainUIdSrcData = {
           .session_id = session_id
    };
    Cond store_data_eigenvalues = {
            .operate = NONE,
            .target = "UID",
            .where_operate = EQUAL,
            .type = LONG,
            .value = (char*)&(((SessionIdObtainUId*)get_module_data(string_hash("user_module"),
                                                                      "SessionIdObtainUID",
                                                                      &sessionIdObtainUIdSrcData,
                                                                      sizeof(sessionIdObtainUIdSrcData)))
                                                                              ->UID),
            .successor = NULL
    };
    MessageSend* send_permission = (get_store_data("PermissionStoreData", &store_data_eigenvalues, user_permission_send_decl, sizeof(MessageSend)).data[0]);
    for (int i = 0; i < send_permission->messageSend_size; i++) {
        if (have_permission(send_permission->messageSend[i], message_send, details)) {
            return true;
        }
    }
    return false;
}
//数据库添加
bool store_add(long long session_id, Details details) {
    SessionIdObtainUIdSrcData sessionIdObtainUIdSrcData = {
           .session_id = session_id
    };
    Cond store_data_eigenvalues = { 
            .operate = NONE,
            .target = "UID",
            .where_operate = EQUAL,
            .type = LONG,
            .value = (char*)&(((SessionIdObtainUId*)get_module_data(string_hash("user_module"),
                                                                      "SessionIdObtainUID",
                                                                      &sessionIdObtainUIdSrcData,
                                                                      sizeof(sessionIdObtainUIdSrcData)))
                                                                              ->UID),
            .successor = NULL
    };
    StoreDataAdd* add_permission = (get_store_data("PermissionStoreData", &store_data_eigenvalues,user_permission_add_decl, sizeof(StoreDataAdd)).data[0]);
    for (int i = 0; i <add_permission->storeDataAdd_size; i++) {
        if (have_permission(add_permission->storeDataAdd[i], store_add, details)) {
            return true;
        }
    }
    return false;
}
//数据库移除
bool store_remove(long long session_id, Details details) {
    SessionIdObtainUIdSrcData sessionIdObtainUIdSrcData = {
           .session_id = session_id
    };
    Cond store_data_eigenvalues = {
            .operate = NONE,
            .target = "UID",
            .where_operate = EQUAL,
            .type = LONG,
            .value = (char*)&(((SessionIdObtainUId*)get_module_data(string_hash("user_module"),
                                                                      "SessionIdObtainUID",
                                                                      &sessionIdObtainUIdSrcData,
                                                                      sizeof(sessionIdObtainUIdSrcData)))
                                                                              ->UID),
            .successor = NULL
    };
    StoreDataRemove* remove_permission = (get_store_data("PermissionStoreData", &store_data_eigenvalues,user_permission_remove_decl, sizeof(StoreDataRemove)).data[0]);
    for (int i = 0; i < remove_permission->storeDataRemove_size; i++) {
        if (have_permission(remove_permission->storeDataRemove[i], store_remove, details)) {
            return true;
        }
    }
    return false;
}
//数据库获取
bool store_get(long long session_id, Details details) {
SessionIdObtainUIdSrcData sessionIdObtainUIdSrcData = {
       .session_id = session_id
};
Cond store_data_eigenvalues = {
        .operate = NONE,
        .target = "UID",
        .where_operate = EQUAL,
        .type = LONG,
        .value = (char*)&(((SessionIdObtainUId*)get_module_data(string_hash("user_module"),
                                                                  "SessionIdObtainUID",
                                                                  &sessionIdObtainUIdSrcData,
                                                                  sizeof(sessionIdObtainUIdSrcData)))
                                                                          ->UID),
        .successor = NULL
};
StoreDataGet* get_permission = (get_store_data("PermissionStoreData", &store_data_eigenvalues, user_permission_get_decl, sizeof(StoreDataGet)).data[0]);
for (int i = 0; i < get_permission->storeDataGet_size; i++) {
    if (have_permission(get_permission->storeDataGet[i], store_get, details)) {
        return true;
    }
}
return false;
}
//其他权限
bool other_data(long long session_id, Details details) {
    SessionIdObtainUIdSrcData sessionIdObtainUIdSrcData = {
           .session_id = session_id
    };
    Cond store_data_eigenvalues = {
            .operate = NONE,
            .target = "UID",
            .where_operate = EQUAL,
            .type = LONG,
            .value = (char*)&(((SessionIdObtainUId*)get_module_data(string_hash("user_module"),
                                                                      "SessionIdObtainUID",
                                                                      &sessionIdObtainUIdSrcData,
                                                                      sizeof(sessionIdObtainUIdSrcData)))
                                                                              ->UID),
            .successor = NULL
    };
    OtherData* other_permission = (get_store_data("PermissionStoreData", &store_data_eigenvalues, user_permission_other_decl, sizeof(OtherData)).data[0]);
    for (int i = 0; i < other_permission->otherData_size; i++) {
        if (have_permission(other_permission->otherData[i], other_data, details)) {
            return true;
        }
    }
    return false;
}
//判断用户组里权限
bool usergroup_permission(long long session_id, Details details) {
    SessionIdObtainUIdSrcData sessionIdObtainUIdSrcData = {
           .session_id = session_id
    };
    Cond store_data_eigenvalues = {
            .operate = NONE,
            .target = "UID",
            .where_operate = EQUAL,
            .type = LONG,
            .value = (char*)&(((SessionIdObtainUId*)get_module_data(string_hash("user_module"),
                                                                      "SessionIdObtainUID",
                                                                      &sessionIdObtainUIdSrcData,
                                                                      sizeof(sessionIdObtainUIdSrcData)))
                                                                              ->UID),
            .successor = NULL
    };
}
//初始化数据库
void initialize_decl_cond(){
    Decl* UID = normal_declaration("UID", LONG);
    Decl* messageSend = normal_declaration("messageSend", LONG);
    messageSend->is_dynamic_array = true;
    Decl* messageAccept = normal_declaration("messageAccept", LONG);
    messageAccept->is_dynamic_array = true;
    Decl*storeDataAdd  = normal_declaration("storeDataAdd", LONG);
    storeDataAdd->is_dynamic_array = true;
    Decl* storeDataRemove = normal_declaration("storeDataRemove", LONG);
    storeDataRemove->is_dynamic_array = true;
    Decl* storeDataUpdate = normal_declaration("storeDataUpdate", LONG);
    storeDataUpdate->is_dynamic_array = true;
    Decl* storeDataGet = normal_declaration("storeDataGet", LONG);
    storeDataGet->is_dynamic_array = true;
    Decl* otherData = normal_declaration("otherData", LONG);
    otherData->is_dynamic_array = true;
    Decl* usergroup_id = normal_declaration("usergroup_id", LONG);

    Decl* b = normal_declaration("b",OBJ );
    b->name = "value";
    b->type = "char";
    b->is_dynamic_array = true;
    Decl* a = object_declaration("a", 1, b);

    permission_store_data_decl = object_declaration("PermissionStoreData", 9, UID, messageSend, messageAccept, storeDataAdd, storeDataRemove, storeDataUpdate, storeDataGet, otherData);
    user_permission_accept_decl = object_declaration("UserAccpetPermission",2,UID, messageAccept);
    user_permission_send_decl = object_declaration("UserSendPermission", 2, UID, messageSend);
    user_permission_add_decl = object_declaration("UserAddPermission", 2, UID, storeDataAdd);
    user_permission_remove_decl = object_declaration("UserRemovePermission", 2, UID, storeDataRemove);
    user_permission_get_decl = object_declaration("UserGetPermission", 2, UID, storeDataGet);
    user_permission_other_decl = object_declaration("UserOtherPermission", 2, UID, otherData);

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



