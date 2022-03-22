//
// Created by lpyyxy on 2022/3/7.
//

#ifndef _PERMISSION_MODULE_MAIN_H_
#define _PERMISSION_MODULE_MAIN_H_

#include <glowworm.h>
#include <stdio.h>
#include"shared.h"
#include"util.h"
typedef struct PermissionStoreData {
	long long UID;
	char* group_id;
	unsigned int group_id_size;
	bool is_success[6];
	long* other_id;
	unsigned int other_id_size;
};

static Decl *permission_store_data_decl;

static Cond* message_submission_cond;

static Cond* message_initialize_cond;
#endif
