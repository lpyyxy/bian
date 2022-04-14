//
// Created by lpyyxy on 2022/3/7.
//

#ifndef _PERMISSION_MODULE_MAIN_H_
#define _PERMISSION_MODULE_MAIN_H_

#include <stdio.h>
#include"shared.h"
#include"util.h"
typedef struct getusergroup_permission{
	unsigned int permission_size;
	String* str_permission;
}getusergroup_permission;

typedef struct Permission {
	unsigned permission_size;
	long long *permission;
}Permission;
typedef struct PermissionStoreData{
	long long UID;

	long long usergroup_id;

	unsigned int messageSend_size;
	Permission* messageSend;

	unsigned int messageAccept_size;
	Permission* messageAccept;

	unsigned int storeDataAdd_size;
	Permission* storeDataAdd;

	unsigned int storeDataRemove_size;
	Permission* storeDataRemove;

	unsigned int storeDataUpdate_size;
	Permission* storeDataUpdate;

	unsigned int storeDataGet_size;
	Permission*storeDataGet;

	unsigned int otherData_size;
	Permission* otherData;

}PermissionStoreData;

typedef struct MessageAccept {
	long long usergroup_id;
	unsigned int messageAccept_size;
	Permission* messageAccept;
}MessageAccept;
typedef struct MessageSend {
	long long usergroup_id;
	unsigned int messageSend_size;
	Permission* messageSend;
}MessageSend;
typedef struct StoreDataAdd {
	long long usergroup_id;
	unsigned int storeDataAdd_size;
	Permission* storeDataAdd;
}StoreDataAdd;
typedef struct StoreDataRemove {
	long long usergroup_id;
	unsigned int storeDataRemove_size;
	Permission* storeDataRemove;
}StoreDataRemove;
typedef struct StoreDataGet {
	long long usergroup_id;
	unsigned int storeDataGet_size;
	Permission* storeDataGet;
}StoreDataGet;
typedef struct OtherData {
	long long usergroup_id;
	unsigned int otherData_size;
	Permission* otherData;
}OtherData;

static Decl *permission_store_data_decl;

static Cond* message_submission_cond;

static Cond* message_initialize_cond;

static BaseEventID* base_event_id;

static Decl* user_permission_accept_decl;
static Decl* user_permission_send_decl;
static Decl* user_permission_add_decl;
static Decl* user_permission_get_decl;
static Decl* user_permission_remove_decl;
static Decl* user_permission_other_decl;
static Permission* temp_permission;
void initialize_decl_cond();
bool message_accept();
bool message_sent();
#endif
