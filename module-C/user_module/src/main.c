//
// Created by lpyyxy on 2022/3/7.
//

#include "main.h"

int index;
long long sid;
int main(void)
{

    Config* config = load_config("config.cfg");
    if (!initialize(hash_string("user_module"),
        find_config(config, "address"),
        find_config(config, "private_key"))) {
        return 0;
    }
    initialize_decl_cond();

    init_store_data("UserStoreData", user_store_data_decl);
    accept_message(message_register_cond, user_information_decl, sizeof(UserInformation), message_register_fun);
    accept_message(message_login_cond, user_information_decl, sizeof(UserInformation), message_login_fun);
    accept_message(message_cancellation_cond, user_information_decl, sizeof(UserInformation), message_login_fun);
    accept_message(message_delete_cond, user_information_decl, sizeof(UserInformation), message_delete_fun);
    accept_message(message_continuous_user_notification_cond, user_information_decl, sizeof(UserInformation), message_continuous_user_notification_fun);
}
void message_continuous_user_notification_fun(long long session_id, void* message) {
    accept_module_message("ContinuousUserNotification", store_message);
    ArrayList* arraylist_message = map_get(store_message_map, map_get(sid_to_uid_map, &session_id));
    sid = session_id;
    for (int i = 0; arraylist_message->length; i++) {
        scheduled_tasks(((NotificationMessage*)get_arraylist(arraylist_message, i))->timestamp, send_message_to_user);
    }
    index = 0;
}

void send_message_to_user() {
    ArrayList* arraylist_message = map_get(store_message_map, map_get(sid_to_uid_map, &sid));
    MessageToUser message_to_user = {
        .id = ((NotificationMessage*)get_arraylist(arraylist_message,index))->id,
        .message = ((NotificationMessage*)get_arraylist(arraylist_message,index))->message,
        .message_size = ((NotificationMessage*)get_arraylist(arraylist_message,index))->message_size,
        .type = ((NotificationMessage*)get_arraylist(arraylist_message,index))->type,
    };
    send_message(&sid, message_to_user_decl, &message_to_user);
    index++;
}


void store_message(NotificationMessage* notificationMessage) {

    if (!map_exist(store_message_map, &notificationMessage->UID)) {
        map_put(store_message_map, &notificationMessage->UID, init_arraylist(sizeof(NotificationMessage)));
    }

    add_arraylist(map_get(store_message_map, &notificationMessage->UID), &notificationMessage);

}

void message_delete_fun(long long session_id, void* message) {
    if (!map_exist(sid_to_uid_map, &session_id)) {
        return;
    }
    long long* UID = map_get(sid_to_uid_map, &session_id);
    ArrayList* arraylist = map_get(uid_to_sid_map, UID);

    for (int i = 0; i < arraylist->length; i++) {
        map_remove(sid_to_uid_map, get_arraylist(arraylist, i), UID);
    }

    map_remove(uid_to_sid_map, UID, map_get(uid_to_sid_map, UID));

    Cond user_UID = {
         .operate = NONE,
         .target = "UID",
         .where_operate = EQUAL,
         .type = LONG,
         .value = long_to_byte_array(UID),
         .successor = NULL,
    };
    remove_store_data("UserStoreData", &user_UID);

    accept_module_message("DeleteUser", module_delete_user);

    IsSuccess is_success = {
          .id = to_string("user"),
          .type = to_string("delete"),
          .response = true
    };
    send_message(session_id, is_success_decl, &is_success);
}


void module_delete_user(void* message) {
    if (!map_exist(uid_to_sid_map, ((TransmitUID*)message)->UID)) {
        return;
    }
    long long* UID = ((TransmitUID*)message)->UID;
    ArrayList* arraylist = map_get(uid_to_sid_map, UID);

    for (int i = 0; i < arraylist->length; i++) {
        map_remove(sid_to_uid_map, get_arraylist(arraylist, i), UID);
    }

    map_remove(uid_to_sid_map, UID, map_get(uid_to_sid_map, UID));

    Cond user_UID = {
         .operate = NONE,
         .target = "UID",
         .where_operate = EQUAL,
         .type = LONG,
         .value = long_to_byte_array(UID),
         .successor = NULL,
    };
    remove_store_data("UserStoreData", &user_UID);
}

void message_cancellation_fun(long long session_id, void* message) {
    if (!map_exist(sid_to_uid_map, &session_id)) {
        return;
    }
    long long* UID = map_get(sid_to_uid_map, &session_id);
    map_remove(sid_to_uid_map, &session_id, UID);

    ArrayList* arraylist = map_get(uid_to_sid_map, UID);
    for (int i = 0; i < arraylist->length; i++) {
        if (*((long long*)(arraylist->array) + i) == session_id) {
            int index = i;
            remove_arraylist(arraylist, index);
            break;
        }
    }
    IsSuccess is_success = {
        .id = to_string("user"),
        .type = to_string("cancellation"),
        .response = true
    };
    send_message(session_id, is_success_decl, &is_success);
}

void message_login_fun(long long session_id, void* message) {
    Cond store_data_name = {
        .operate = NONE,
        .target = "name",
        .where_operate = EQUAL,
        .type = OBJ,
        .value = ((UserInformation*)message)->name,
        .successor = NULL

    };

    StoreData temp_store_data;
    if (!((temp_store_data = get_store_data("UserStoreData", &store_data_name, user_store_data_decl, sizeof(UserStoreDate))).data_size)) {
        return;
    }

    for (int i = 0; i < 32; i++) {
        if (((UserInformation*)message)->encryption_password[i] != ((UserStoreDate*)temp_store_data.data[0])->encryption_password[i])
            return;
    }
    long long* UID = ((UserStoreDate*)temp_store_data.data[0])->UID;

    map_put(sid_to_uid_map, &session_id, UID);

    if (!map_exist(uid_to_sid_map, &UID)) {
        map_put(uid_to_sid_map, UID, init_arraylist(sizeof(long long)));
    }

    add_arraylist(map_get(uid_to_sid_map, UID), &session_id);

    put_module_data("SessionIdObtainUID", sizeof(SessionIdObtainUId), SessionIdObtainUID);

    IsSuccess is_success = {
        .id = to_string("user"),
        .type = to_string("login"),
        .response = true
    };
    send_message(session_id, is_success_decl, &is_success);
}
SessionIdObtainUId SessionIdObtainUID(SessionIdObtainUIdSrcData* sessionIdObtainUIdSrcData) {
    SessionIdObtainUId sessionIdObtainUId = {
        .UID = map_get(sid_to_uid_map, &sessionIdObtainUIdSrcData->session_id)
    };
    return sessionIdObtainUId;
}

void message_register_fun(long long session_id, void* message) {
    Cond store_data_name = {
        .operate = NONE,
        .target = "name",
        .where_operate = EQUAL,
        .type = OBJ,
        .value = ((UserInformation*)message)->name,
        .successor = NULL

    };

    StoreData temp_storedata_name;
    if ((temp_storedata_name = get_store_data("UserStoreData", &store_data_name, user_information_decl, sizeof(UserInformation))).data_size) {
        free((UserInformation*)temp_storedata_name.data[0]);
        return;
    }


    UserStoreDate user_store_data;
    bool cnt = false;
    user_store_data.UID =
        hash_array(((UserInformation*)message)->name, ((UserInformation*)message)->name_size) &
        hash_array(((UserInformation*)message)->encryption_password, 32) & get_timestamp();
    user_store_data.name = ((UserInformation*)message)->name;
    user_store_data.name_size = ((UserInformation*)message)->name_size;
    int i;
    for (i = 0; i < 32; i++) {
        user_store_data.encryption_password[i] = ((UserInformation*)message)->encryption_password[i];
    }
    do {

        StoreData temp_storedata_UID;

        Cond store_data_UID = {
             .operate = NONE,
             .target = "UID",
             .where_operate = EQUAL,
             .type = LONG,
             .value = long_to_byte_array(user_store_data.UID),
             .successor = NULL

        };
        cnt = ((temp_storedata_UID = get_store_data("UserStoreData", &store_data_UID, user_store_data_decl, sizeof(UserStoreDate))).data_size);

        free((UserStoreDate*)temp_storedata_UID.data[0]);
    } while (cnt && user_store_data.UID++);
    add_store_data("UserStoreData", &user_store_data);

    free((UserInformation*)temp_storedata_name.data[0]);

    IsSuccess is_success = {
         .id = to_string("user"),
         .type = to_string("register"),
         .response = true
    };
    send_message(session_id, is_success_decl, &is_success);
}
void initialize_decl_cond() {
    Decl* UID = normal_declaration("UID", LONG);
    Decl* name = normal_declaration("name", BYTE);
    name->is_dynamic_array = true;
    Decl* encryption_password = normal_declaration("encryption_password", BYTE);
    encryption_password->array_size = 32;
    user_store_data_decl = object_declaration("UserStoreDate", 3, UID, name, encryption_password);

    user_information_decl = object_declaration("UserInformation", 2, name, encryption_password);

    Decl* value = normal_declaration("value", BYTE);
    value->is_dynamic_array = true;
    Decl* id = object_declaration("id", 1, value);
    Decl* type = object_declaration("type", 1, value);
    Decl* response = normal_declaration("response", BOOLEAN);
    is_success_decl = object_declaration("is_success", 3, id, type, response);

    Decl* message = normal_declaration("message", BYTE);
    message->is_dynamic_array = true;
    Decl* timestamp = normal_declaration("timestamp", LONG);
    notification_message_decl = object_declaration("NotificationMessage", 5, UID, id, type, message, timestamp);

    message_to_user_decl = object_declaration("MessageToUser", 3, id, type, message);

    Cond message_register_2 = {
            .operate = NONE,
            .target = "type",
            .where_operate = EQUAL,
            .type = OBJ,
            .value = "register",
            .successor = NULL
    };
    Cond message_register_1 = {
            .operate = AND,
            .target = "id",
            .where_operate = EQUAL,
            .type = OBJ,
            .value = "user",
            .successor = &message_register_2

    };

    Cond message_login_2 = {
           .operate = NONE,
           .target = "type",
           .where_operate = EQUAL,
           .type = OBJ,
           .value = "login",
           .successor = NULL
    };

    Cond message_login_1 = {
           .operate = AND,
           .target = "id",
           .where_operate = EQUAL,
           .type = OBJ,
           .value = "user",
           .successor = &message_login_2

    };

    Cond message_cancellation_2 = {
          .operate = NONE,
          .target = "type",
          .where_operate = EQUAL,
          .type = OBJ,
          .value = "cancellation",
          .successor = NULL
    };

    Cond message_cancellation_1 = {
           .operate = AND,
           .target = "id",
           .where_operate = EQUAL,
           .type = OBJ,
           .value = "user",
           .successor = &message_cancellation_2

    };

    Cond message_delete_2 = {
        .operate = NONE,
        .target = "type",
        .where_operate = EQUAL,
        .type = OBJ,
        .value = "cancellation",
        .successor = NULL
    };

    Cond message_delete_1 = {
           .operate = AND,
           .target = "id",
           .where_operate = EQUAL,
           .type = OBJ,
           .value = "user",
           .successor = &message_delete_2

    };

    Cond message_continuous_user_notification_2 = {
      .operate = NONE,
      .target = "type",
      .where_operate = EQUAL,
      .type = OBJ,
      .value = "continuous_user_notification",
      .successor = NULL
    };

    Cond message_continuous_user_notification_1 = {
        .operate = AND,
        .target = "id",
        .where_operate = EQUAL,
        .type = OBJ,
        .value = "user",
        .successor = &message_continuous_user_notification_2
    };

    message_register_cond = &message_register_1;
    message_login_cond = &message_login_1;
    message_cancellation_cond = &message_cancellation_1;
    message_delete_cond = &message_delete_1;
    message_continuous_user_notification_cond = &message_continuous_user_notification_1;
}

void initialize_map()
{
    sid_to_uid_map = malloc(sizeof(Map));
    sid_to_uid_map->equals = sid_to_uid_equals;
    sid_to_uid_map->hash = sid_to_uid_hash;

    sid_to_uid_map = malloc(sizeof(Map));
    uid_to_sid_map->equals = uid_to_sid_equals;
    uid_to_sid_map->hash = uid_to_sid_hash;

    store_message_map = malloc(sizeof(Map));
    store_message_map->equals = store_message_equals;
    store_message_map->hash = store_message_hash;
}

long long sid_to_uid_hash(void* key) {
    return *((long long*)key);
}

bool sid_to_uid_equals(void* tar_key, void* src_key) {
    return  *(long long*)tar_key == *(long long*)src_key;
}

long long uid_to_sid_hash(void* key) {
    return *((long long*)key);
}

bool uid_to_sid_equals(void* tar_key, void* src_key) {
    return  *(long long*)tar_key == *(long long*)src_key;
}

long long store_message_hash(void* key) {
    return *((long long*)key);
}

bool store_message_equals(void* tar_key, void* src_key) {
    return  *(long long*)tar_key == *(long long*)src_key;
}