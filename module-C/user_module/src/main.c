//
// Created by lpyyxy on 2022/3/7.
//

#include "main.h"


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
}
    void message_cancellation_fun(long long session_id, void* message){

    
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

        map_put(uid_to_sid_map, UID, &session_id);
        if (!map_exist(uid_to_sid_map, &UID)) {
            sid_to_uid_map->map_datum->value = init_arraylist(sizeof(long long));
        }
         
        add_arraylist(sid_to_uid_map->map_datum->value, map_get(uid_to_sid_map, UID));

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
    void message_register_fun(long long session_id, void* message){
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
                    hash_array(((UserInformation *) message)->name, ((UserInformation *) message)->name_size) &
                                  hash_array(((UserInformation *) message)->encryption_password, 32) & get_timestamp();
            user_store_data.name = ((UserInformation*)message)->name;
            user_store_data.name_size = ((UserInformation*)message)->name_size;
            int i;
            for (i = 0; i < 32; i++) {
                user_store_data.encryption_password[i] = ((UserInformation*)message)->encryption_password[i];
            }
            do {
               
                StoreData temp_storedata_UID;
               
                user_store_data.UID++;
               
                Cond store_data_UID = {
                     .operate = NONE,
                     .target = "UID",
                     .where_operate = EQUAL,
                     .type = LONG,
                     .value = long_to_byte_array(user_store_data.UID),
                     .successor = NULL

                };
                cnt =((temp_storedata_UID = get_store_data("UserStoreData", &store_data_UID, user_store_data_decl, sizeof(UserStoreDate))).data_size);
               
                free((UserStoreDate*)temp_storedata_UID.data[0]);
            } while (cnt);
            add_store_data("UserStoreData", &user_store_data);
            
            free((UserInformation*)temp_storedata_name.data[0]);
}
void initialize_decl_cond(){
    Decl* UID = normal_declaration("UID", LONG);
    Decl* name = normal_declaration("name", BYTE);
    name->is_dynamic_array = true;
    Decl* encryption_password = normal_declaration("encryption_password", BYTE);
    encryption_password->array_size = 32;
    user_store_data_decl = object_declaration("UserStoreDate", 3, UID, name, encryption_password);

    user_information_decl = object_declaration("UserInformation", 2,name, encryption_password);

    Decl* value = normal_declaration("value", BYTE);
    value->is_dynamic_array = true;
    Decl* id = object_declaration("id", 1, value);
    Decl* type = object_declaration("type", 1, value);
    Decl* response = normal_declaration("response", BOOLEAN);
    is_success_decl = object_declaration("is_success", 3, id, type, response);


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
    message_register_cond = &message_register_1;
    message_login_cond = &message_login_1;
    message_cancellation_cond = &message_cancellation_1;
}

void initialize_map() 
{
    sid_to_uid_map=malloc(sizeof(Map));
    sid_to_uid_map->equals = sid_to_uid_equals;
    sid_to_uid_map->hash = sid_to_uid_hash;
    
    sid_to_uid_map = malloc(sizeof(Map));
    uid_to_sid_map->equals = uid_to_sid_equals;
    uid_to_sid_map->hash = uid_to_sid_hash;
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