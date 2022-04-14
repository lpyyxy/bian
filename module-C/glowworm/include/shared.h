//
// Created by lpyyxy on 2022/3/10.
//

#ifndef _SHARED_H_
#define _SHARED_H_

typedef struct SessionIdObtainUIdSrcData{
    long long session_id;
}SessionIdObtainUIdSrcData;

typedef struct SessionIdObtainUId{
    long long UID;
}SessionIdObtainUId;

typedef struct TransmitUID {
    long long UID;
}TransmitUID;

typedef struct NotificationMessage {
    long long UID;
    unsigned int message_size;
    void* message;
    char* id;
    char* type;
    long long timestamp;
}NotificationMessage;

#endif
