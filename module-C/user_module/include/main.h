//
// Created by lpyyxy on 2022/3/7.
//

#ifndef _USER_MODULE_MAIN_H_
#define _USER_MODULE_MAIN_H_

#include <glowworm.h>
#include <stdio.h>
#include "util.h"
#include "shared.h"
#include<string.h>

typedef struct UserStoreDate {
	long long UID;
	unsigned int name_size;
	void* name;
	char encryption_password[32];
}UserStoreDate;

typedef struct UserInformation {
	unsigned int name_size;
	void* name;
	char encryption_password[32];
}UserInformation;

typedef struct IsSuccess {
	String id;
	String type;
	bool response;
}IsSuccess;

static Decl* user_store_data_decl;
static Decl* user_information_decl;
static Cond* message_register_cond;
static Cond* message_login_cond;
static Cond* message_cancellation_cond;
static Cond* is_success_decl;

void initialize_decl_cond();
void message_register_fun(long long session_id, void* message);
void message_login_fun(long long session_id, void* message);
void message_cancellation_fun(long long session_id, void* message);

static Map* sid_to_uid_map;
static Map* uid_to_sid_map;
#endif
