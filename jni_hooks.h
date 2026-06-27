#pragma once
#include <jni.h>
#include <cstdint>

namespace jni {

bool CaptureClientThreadEnv(void (*callback)(JNIEnv*));
void Cleanup();
JNIEnv* GetEnv();
void WriteLog(const char* fmt, ...);

}
