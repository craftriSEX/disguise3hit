#include "hit3fix.h"
#include "jni_hooks.h"
#include <windows.h>
#include <cstdio>
#include <thread>
#include <chrono>
#include <string>
#include <set>

namespace hit3fix {

static bool g_ready = false;
static bool g_running = false;
static std::thread g_worker;

#define F(env) ((env)->functions)
#include <jvmti.h>

static void InitFiles() {
    CreateDirectoryA("C:\\craftrise", NULL);
    const char* names[] = {"log.txt","classes.txt","thread.txt"};
    for (auto n : names) {
        char p[80]; sprintf_s(p, "C:\\craftrise\\%s", n);
        FILE* f = fopen(p, "w");
        if (f) { fprintf(f, "[@minhook.h] started\n"); fclose(f); }
    }
}

static void LogThread(JNIEnv* env) {
    auto fc   = F(env)->FindClass;
    auto gmid = F(env)->GetMethodID;
    auto gsmid= F(env)->GetStaticMethodID;
    auto com  = F(env)->CallObjectMethod;
    auto csom = F(env)->CallStaticObjectMethod;
    auto cim  = F(env)->CallIntMethod;
    auto gsu  = F(env)->GetStringUTFChars;
    auto rsu  = F(env)->ReleaseStringUTFChars;
    auto dlr  = F(env)->DeleteLocalRef;

    DWORD tid = GetCurrentThreadId();
    jni::WriteLog("ON CLIENT THREAD TID=%lu", tid);

    jclass tc = fc(env, "java/lang/Thread");
    if (!tc) { jni::WriteLog("no Thread class"); return; }
    jmethodID curM = gsmid(env, tc, "currentThread", "()Ljava/lang/Thread;");
    jmethodID gnM  = gmid(env, tc, "getName", "()Ljava/lang/String;");
    jmethodID gpM  = gmid(env, tc, "getPriority", "()I");
    jmethodID gtgM = gmid(env, tc, "getThreadGroup", "()Ljava/lang/ThreadGroup;");

    jobject th = csom(env, tc, curM);
    if (!th) { jni::WriteLog("no thread obj"); dlr(env, tc); return; }
    jstring ns = (jstring)com(env, th, gnM);
    const char* tn = ns ? gsu(env, ns, nullptr) : "?";
    jint prio = cim(env, th, gpM);

    FILE* f = fopen("C:\\craftrise\\thread.txt", "w");
    if (f) {
        fprintf(f, "[Client Thread]\n");
        fprintf(f, "  Windows TID: %lu\n", tid);
        fprintf(f, "  JNIEnv: %p\n", (void*)env);
        fprintf(f, "  Java Name: %s\n", tn ? tn : "?");
        fprintf(f, "  Priority: %d\n", prio);

        jobject tg = com(env, th, gtgM);
        if (tg) {
            jclass tgc = fc(env, "java/lang/ThreadGroup");
            jmethodID tgnM = gmid(env, tgc, "getName", "()Ljava/lang/String;");
            jstring tgs = (jstring)com(env, tg, tgnM);
            if (tgs) { const char* c = gsu(env, tgs, nullptr);
                if (c) { fprintf(f, "  ThreadGroup: %s\n", c); rsu(env, tgs, c); } }
            dlr(env, tgc); dlr(env, tg);
        }

        jmethodID gcclM = gmid(env, tc, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
        if (gcclM) {
            jobject cl = com(env, th, gcclM);
            if (cl) {
                jclass cc = fc(env, "java/lang/Class");
                jmethodID cnM = gmid(env, cc, "getName", "()Ljava/lang/String;");
                jstring cs = (jstring)com(env, cl, cnM);
                if (cs) { const char* c2 = gsu(env, cs, nullptr);
                    if (c2) { fprintf(f, "  ClassLoader: %s\n", c2); rsu(env, cs, c2); } }
                dlr(env, cc); dlr(env, cl);
            }
        }
        fclose(f);
    }
    if (tn && ns) rsu(env, ns, tn);
    dlr(env, th); dlr(env, tc);
    jni::WriteLog("thread.txt written");
}

static void DumpClasses(JNIEnv* env) {
    JavaVM* vm = nullptr;
    if (F(env)->GetJavaVM(env, &vm) != JNI_OK || !vm) { jni::WriteLog("GetJavaVM failed"); return; }
    jni::WriteLog("JavaVM = %p", (void*)vm);

    jvmtiEnv* jvmti = nullptr;
    auto invokeIface = *(const struct JNIInvokeInterface_**)vm;
    int verTry = 0;
    jint jvmtVersions[] = {JVMTI_VERSION_1_2, JVMTI_VERSION_1_1, JVMTI_VERSION_1_0};
    for (; verTry < 3; verTry++) {
        jvmti = nullptr;
        jint r = invokeIface->GetEnv(vm, (void**)&jvmti, jvmtVersions[verTry]);
        if (r == JNI_OK && jvmti) break;
    }
    if (!jvmti) { jni::WriteLog("GetEnv JVMTI failed"); return; }
    jni::WriteLog("JVMTI = %p", (void*)jvmti);

    auto iface = *(const struct jvmtiInterface_1_**)jvmti;

    jint count = 0;
    jclass* classes = nullptr;
    if (iface->GetLoadedClasses(jvmti, &count, &classes) != JVMTI_ERROR_NONE) {
        jni::WriteLog("GetLoadedClasses error"); return;
    }
    jni::WriteLog("%d classes returned", count);

    auto goc  = F(env)->GetObjectClass;
    auto gmid = F(env)->GetMethodID;
    auto com  = F(env)->CallObjectMethod;
    auto gsu  = F(env)->GetStringUTFChars;
    auto rsu  = F(env)->ReleaseStringUTFChars;

    jclass classClass = goc(env, (jobject)classes[0]);
    jmethodID getNameM = gmid(env, classClass, "getName", "()Ljava/lang/String;");

    FILE* f = fopen("C:\\craftrise\\classes.txt", "w");
    if (!f) { iface->Deallocate(jvmti, (unsigned char*)classes); return; }

    int success = 0;
    for (jint i = 0; i < count; i++) {
        jstring name = (jstring)com(env, (jobject)classes[i], getNameM);
        if (!name) continue;
        const char* cc = gsu(env, name, nullptr);
        if (cc) {
            fprintf(f, "[W] class -> %s\n", cc);
            rsu(env, name, cc);
            success++;
        }
    }

    iface->Deallocate(jvmti, (unsigned char*)classes);
    fclose(f);
    jni::WriteLog("%d classes written", success);
}

static void VehWork(JNIEnv* env) {
    jni::WriteLog("VEH callback on Client Thread TID=%lu", GetCurrentThreadId());
    LogThread(env);
    DumpClasses(env);
    jni::WriteLog("VEH callback done");
}

static void Worker() {
    InitFiles();
    jni::WriteLog("waiting for Client Thread via VEH+INT3...");
    if (!jni::CaptureClientThreadEnv(VehWork)) {
        jni::WriteLog("failed");
        return;
    }
    jni::WriteLog("all done");
    g_ready = true;
}

bool Initialize() {
    if (g_running) return true;
    g_running = true;
    g_worker = std::thread(Worker);
    g_worker.detach();
    return true;
}

void Shutdown() { g_running = false; g_ready = false; jni::Cleanup(); }
bool IsReady() { return g_ready; }

}
