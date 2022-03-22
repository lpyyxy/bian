//
// Created by lpyyxy on 2022/3/10.
//

#ifndef _SHARED_H_
#define _SHARED_H_

typedef struct SessionIdObtainUIdSrcData{
    long long session_id;//服务端和客户端连接生成的
}SessionIdObtainUIdSrcData;
 
typedef struct SessionIdObtainUId{
    long long u_Id;//用户和用户模块交互时产生的id
}SessionIdObtainUId;


#endif
