// 作者：pxx917144686

// ============== 头文件 ==============
// 引入必要的标准头文件，确保独立性
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <UserNotifications/UserNotifications.h> // 用于通知功能
#include <dlfcn.h> // 用于动态加载函数
#include <objc/runtime.h> // 用于 Objective-C 运行时操作
#include <CommonCrypto/CommonCryptor.h> // AES 加密支持
#include <mach-o/dyld.h> // 获取动态链接信息
#include <sys/sysctl.h> // 系统控制
#include <sys/types.h>
#include <unistd.h> // Unix 标准函数，包括 usleep
#include <execinfo.h> // 用于 backtrace 获取调用栈

// 定义 PT_DENY_ATTACH 常量，避免依赖 sys/ptrace.h
#define PT_DENY_ATTACH 31

// 配置类：管理伪装和推送相关配置
@interface HookConfig : NSObject
@property (nonatomic, strong) NSDictionary *fakeInfoPlist; // 伪装 Info.plist 数据
@property (nonatomic, assign) NSTimeInterval minPollingInterval; // 最小轮询间隔
@property (nonatomic, assign) NSTimeInterval maxPollingInterval; // 最大轮询间隔
@property (nonatomic, strong) NSData *encryptionKey; // AES 加密密钥
+ (instancetype)sharedConfig; // 单例方法，用于获取全局配置实例
@end

// NSBundle 的 Category 接口扩展：用于 Hook NSBundle 方法以实现伪装
@interface NSBundle (Hook)
+ (void)zcxd_startHook; // 初始化 Hook
+ (void)zcxd_actionHook; // 执行 Hook 操作
- (BOOL)shouldHookAt:(NSString *)path; // 判断是否需要 Hook
- (NSString *)zcxd_bundleIdentifier; // Hook bundleIdentifier
- (NSDictionary *)zcxd_infoDictionary; // Hook infoDictionary
- (id)zcxd_objectForInfoDictionaryKey:(NSString *)key; // Hook objectForInfoDictionaryKey
- (BOOL)hook_fileExistsAtPath:(NSString *)path; // Hook fileExistsAtPath
- (BOOL)hook_fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir; // Hook fileExistsAtPath:isDirectory:
@end

// 推送管理类接口：实现模拟推送功能
@interface PushManager : NSObject
@property (nonatomic, strong) NSTimer *pollingTimer; // 轮询定时器
@property (nonatomic, strong) NSTimer *webSocketTimer; // 模拟 WebSocket 定时器
@property (nonatomic, assign) NSTimeInterval currentPollingInterval; // 当前轮询间隔
@property (nonatomic, copy) void (^messageHandler)(id message); // 消息处理回调
@property (nonatomic, assign) NSTimeInterval lastHeartbeatTime; // 上次心跳时间

+ (instancetype)sharedManager; // 单例方法
- (void)startPollingWithHandler:(void (^)(id message))handler; // 启动轮询
- (void)stopPolling; // 停止轮询
- (void)startWebSocketWithHandler:(void (^)(id message))handler; // 启动模拟 WebSocket
- (void)stopWebSocket; // 停止模拟 WebSocket
- (void)showLocalNotificationWithMessage:(NSString *)message; // 显示本地通知
@end

// 全局变量：用于 Hook 的原始 IMP 和单次初始化标记
static dispatch_once_t zcxd_startHook_onceToken = 0;
static IMP originalBundleIdentifierIMP = NULL;
static IMP originalInfoDictionaryIMP = NULL;
static IMP originalObjectForInfoDictionaryKeyIMP = NULL;
static IMP originalFileExistsAtPathIMP = NULL;
static IMP originalFileExistsAtPathIsDirectoryIMP = NULL;

// 防越狱检测：常见越狱路径列表
static NSArray *jailbreakPaths = @[
    @"/Applications/Cydia.app", @"/usr/bin/ssh", @"/var/lib/cydia",
    @"/private/var/lib/dpkg/", @"/private/var/db/stash/",
    @"/var/jb", @"/var/jb/bin", @"/var/jb/usr/lib"
];

// 获取调用者路径：隐藏越狱痕迹，返回伪装路径
static NSString *getCallerPath() {
    void *callstack[128];
    int frames = backtrace(callstack, 128); // 获取调用栈
    for (int i = 1; i < frames; i++) {
        Dl_info info;
        if (dladdr(callstack[i], &info) && info.dli_fname) {
            NSString *path = [NSString stringWithUTF8String:info.dli_fname];
            for (NSString *jbPath in jailbreakPaths) {
                if ([path hasPrefix:jbPath]) {
                    return [[NSBundle mainBundle] executablePath]; // 若检测到越狱路径，返回伪装路径
                }
            }
            return path; // 返回正常路径
        }
    }
    return [[NSBundle mainBundle] executablePath]; // 默认返回合法路径
}

// HookConfig 实现
@implementation HookConfig

+ (instancetype)sharedConfig {
    static HookConfig *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
        sharedInstance.fakeInfoPlist = @{@"CFBundleIdentifier": @"com.tencent.xin", @"CFBundleName": @"WeChat"};
        sharedInstance.minPollingInterval = 5.0; // 设置最小轮询间隔为 5 秒
        sharedInstance.maxPollingInterval = 15.0; // 设置最大轮询间隔为 15 秒
        sharedInstance.encryptionKey = [sharedInstance generateEncryptionKey]; // 生成加密密钥
    });
    return sharedInstance;
}

// 生成 AES 加密密钥
- (NSData *)generateEncryptionKey {
    NSMutableData *key = [NSMutableData dataWithLength:kCCKeySizeAES256];
    (void)SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES256, key.mutableBytes); // 生成随机密钥，忽略返回值警告
    return key;
}

@end

// NSBundle 的 Category 实现
@implementation NSBundle (Hook)

+ (void)load {
    [self zcxd_startHook]; // 在类加载时启动 Hook
}

+ (void)zcxd_startHook {
    dispatch_once(&zcxd_startHook_onceToken, ^{
        [self zcxd_actionHook]; // 单次执行 Hook 操作
    });
}

+ (void)zcxd_actionHook {
    // Hook bundleIdentifier 方法
    Method origMethod = class_getInstanceMethod(self, @selector(bundleIdentifier));
    Method hookMethod = class_getInstanceMethod(self, @selector(zcxd_bundleIdentifier));
    originalBundleIdentifierIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);

    // Hook infoDictionary 方法
    origMethod = class_getInstanceMethod(self, @selector(infoDictionary));
    hookMethod = class_getInstanceMethod(self, @selector(zcxd_infoDictionary));
    originalInfoDictionaryIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);

    // Hook objectForInfoDictionaryKey 方法
    origMethod = class_getInstanceMethod(self, @selector(objectForInfoDictionaryKey:));
    hookMethod = class_getInstanceMethod(self, @selector(zcxd_objectForInfoDictionaryKey:));
    originalObjectForInfoDictionaryKeyIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);

    // Hook NSFileManager 的 fileExistsAtPath 方法
    origMethod = class_getInstanceMethod(objc_getClass("NSFileManager"), @selector(fileExistsAtPath:));
    hookMethod = class_getInstanceMethod(self, @selector(hook_fileExistsAtPath:));
    originalFileExistsAtPathIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);

    // Hook NSFileManager 的 fileExistsAtPath:isDirectory: 方法
    origMethod = class_getInstanceMethod(objc_getClass("NSFileManager"), @selector(fileExistsAtPath:isDirectory:));
    hookMethod = class_getInstanceMethod(self, @selector(hook_fileExistsAtPath:isDirectory:));
    originalFileExistsAtPathIsDirectoryIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);
}

- (BOOL)shouldHookAt:(NSString *)path {
    if (!path) return NO; // 如果路径为空，不 Hook
    NSString *mainBundlePath = [[NSBundle mainBundle] bundlePath];
    if ([path hasPrefix:mainBundlePath]) {
        NSString *executablePath = [[NSBundle mainBundle] executablePath];
        if ([path isEqualToString:executablePath]) return YES; // 如果是主程序路径，Hook
        NSArray *frameworks = @[
            @"/Frameworks/JavaScriptCore2.framework/JavaScriptCore2",
            @"/Frameworks/NewMessageRingUtil.framework/NewMessageRingUtil"
        ];
        for (NSString *framework in frameworks) {
            if ([path isEqualToString:[mainBundlePath stringByAppendingPathComponent:framework]]) return YES; // 如果是指定框架路径，Hook
        }
    }
    return NO; // 默认不 Hook
}

- (NSString *)zcxd_bundleIdentifier {
    NSString *callerPath = getCallerPath();
    if (self == [NSBundle mainBundle] && [self shouldHookAt:callerPath]) {
        return [HookConfig sharedConfig].fakeInfoPlist[@"CFBundleIdentifier"]; // 返回伪装的 Bundle ID
    }
    return ((NSString * (*)(id, SEL))originalBundleIdentifierIMP)(self, @selector(bundleIdentifier)); // 调用原始方法
}

- (NSDictionary *)zcxd_infoDictionary {
    NSString *callerPath = getCallerPath();
    if (self == [NSBundle mainBundle] && [self shouldHookAt:callerPath]) {
        NSDictionary *origDict = ((NSDictionary * (*)(id, SEL))originalInfoDictionaryIMP)(self, @selector(infoDictionary));
        NSMutableDictionary *dict = [origDict mutableCopy];
        [dict addEntriesFromDictionary:[HookConfig sharedConfig].fakeInfoPlist]; // 添加伪装数据
        return dict;
    }
    return ((NSDictionary * (*)(id, SEL))originalInfoDictionaryIMP)(self, @selector(infoDictionary)); // 调用原始方法
}

- (id)zcxd_objectForInfoDictionaryKey:(NSString *)key {
    NSString *callerPath = getCallerPath();
    if (self == [NSBundle mainBundle] && [self shouldHookAt:callerPath]) {
        id fakeValue = [HookConfig sharedConfig].fakeInfoPlist[key];
        if (fakeValue) return fakeValue; // 返回伪装值
    }
    return ((id (*)(id, SEL, NSString *))originalObjectForInfoDictionaryKeyIMP)(self, @selector(objectForInfoDictionaryKey:), key); // 调用原始方法
}

// Hook NSFileManager 的 fileExistsAtPath 方法
- (BOOL)hook_fileExistsAtPath:(NSString *)path {
    for (NSString *jbPath in jailbreakPaths) {
        if ([path hasPrefix:jbPath]) {
            return NO; // 隐藏越狱路径
        }
    }
    return ((BOOL (*)(id, SEL, NSString *))originalFileExistsAtPathIMP)(self, @selector(hook_fileExistsAtPath:), path); // 调用原始方法
}

// Hook NSFileManager 的 fileExistsAtPath:isDirectory: 方法
- (BOOL)hook_fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir {
    for (NSString *jbPath in jailbreakPaths) {
        if ([path hasPrefix:jbPath]) {
            return NO; // 隐藏越狱路径
        }
    }
    return ((BOOL (*)(id, SEL, NSString *, BOOL *))originalFileExistsAtPathIsDirectoryIMP)(self, @selector(hook_fileExistsAtPath:isDirectory:), path, isDir); // 调用原始方法
}

@end

// PushManager 实现
@implementation PushManager

+ (instancetype)sharedManager {
    static PushManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _currentPollingInterval = [HookConfig sharedConfig].minPollingInterval; // 初始化轮询间隔
        _lastHeartbeatTime = 0; // 初始化心跳时间
        // 注册应用生命周期通知
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(applicationDidEnterBackground)
                                                 name:UIApplicationDidEnterBackgroundNotification
                                                 object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(applicationDidBecomeActive)
                                                 name:UIApplicationDidBecomeActiveNotification
                                                 object:nil];
    }
    return self;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-missing-super-calls"
- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self]; // 移除通知观察者
    [self stopPolling]; // 停止轮询
    [self stopWebSocket]; // 停止模拟 WebSocket
    // 使用 ARC，无需显式调用 [super dealloc]
}
#pragma clang diagnostic pop

// 启动模拟轮询
- (void)startPollingWithHandler:(void (^)(id message))handler {
    self.messageHandler = handler;
    [self stopPolling]; // 先停止现有轮询
    self.currentPollingInterval = [self predictPollingInterval];
    self.pollingTimer = [NSTimer scheduledTimerWithTimeInterval:self.currentPollingInterval
                                                         target:self
                                                       selector:@selector(checkForNewMessages)
                                                       userInfo:nil
                                                        repeats:YES];
}

// 停止轮询
- (void)stopPolling {
    [self.pollingTimer invalidate];
    self.pollingTimer = nil;
}

// 计算轮询间隔（随机生成）
- (NSTimeInterval)predictPollingInterval {
    NSTimeInterval minInterval = [HookConfig sharedConfig].minPollingInterval;
    NSTimeInterval maxInterval = [HookConfig sharedConfig].maxPollingInterval;
    return minInterval + arc4random_uniform((uint32_t)(maxInterval - minInterval));
}

// 模拟检查新消息
- (void)checkForNewMessages {
    NSString *simulatedMessage = [self generateSimulatedMessage];
    NSData *encryptedData = [self encryptMessage:simulatedMessage];
    NSString *decryptedMessage = [self decryptMessage:encryptedData];
    if (decryptedMessage && self.messageHandler) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.messageHandler(decryptedMessage);
            [self showLocalNotificationWithMessage:decryptedMessage]; // 显示通知
        });
    }
    self.currentPollingInterval = [self predictPollingInterval];
    [self.pollingTimer setFireDate:[NSDate dateWithTimeIntervalSinceNow:self.currentPollingInterval]];
}

// 启动模拟 WebSocket
- (void)startWebSocketWithHandler:(void (^)(id message))handler {
    [self stopWebSocket]; // 先停止现有 WebSocket
    self.messageHandler = handler;
    self.webSocketTimer = [NSTimer scheduledTimerWithTimeInterval:10.0
                                                           target:self
                                                         selector:@selector(simulateWebSocketMessage)
                                                         userInfo:nil
                                                          repeats:YES];
    self.lastHeartbeatTime = [[NSDate date] timeIntervalSince1970];
}

// 停止模拟 WebSocket
- (void)stopWebSocket {
    [self.webSocketTimer invalidate];
    self.webSocketTimer = nil;
}

// 模拟 WebSocket 消息
- (void)simulateWebSocketMessage {
    NSString *simulatedMessage = [self generateSimulatedMessage];
    NSData *encryptedData = [self encryptMessage:simulatedMessage];
    NSString *decryptedMessage = [self decryptMessage:encryptedData];
    if (decryptedMessage && self.messageHandler) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.messageHandler(decryptedMessage);
            [self showLocalNotificationWithMessage:decryptedMessage]; // 显示通知
        });
    }
    [self simulateHeartbeat];
}

// 模拟心跳
- (void)simulateHeartbeat {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - self.lastHeartbeatTime > 30.0) {
        self.lastHeartbeatTime = now; // 更新心跳时间
    }
}

// 生成模拟消息
- (NSString *)generateSimulatedMessage {
    NSArray *messages = @[
        @"你有一条新消息！",
        @"朋友圈有更新，快来看看吧！",
        @"有人@你在群聊中。",
        @"收到一条语音消息。"
    ];
    return messages[arc4random_uniform((uint32_t)messages.count)];
}

// 消息加密（AES）
- (NSData *)encryptMessage:(NSString *)message {
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus status = CCCrypt(kCCEncrypt,
                                     kCCAlgorithmAES,
                                     kCCOptionPKCS7Padding,
                                     [HookConfig sharedConfig].encryptionKey.bytes,
                                     kCCKeySizeAES256,
                                     NULL,
                                     [data bytes],
                                     [data length],
                                     buffer,
                                     bufferSize,
                                     &numBytesEncrypted);
    if (status == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted freeWhenDone:YES];
    }
    free(buffer);
    return nil;
}

// 消息解密（AES）
- (NSString *)decryptMessage:(NSData *)data {
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt,
                                     kCCAlgorithmAES,
                                     kCCOptionPKCS7Padding,
                                     [HookConfig sharedConfig].encryptionKey.bytes,
                                     kCCKeySizeAES256,
                                     NULL,
                                     [data bytes],
                                     [data length],
                                     buffer,
                                     bufferSize,
                                     &numBytesDecrypted);
    if (status == kCCSuccess) {
        NSData *decryptedData = [NSData dataWithBytes:buffer length:numBytesDecrypted];
        free(buffer);
        return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    }
    free(buffer);
    return nil;
}

// 显示本地通知
- (void)showLocalNotificationWithMessage:(NSString *)message {
    UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
    content.title = @"WeChat";
    content.body = message;
    content.sound = [UNNotificationSound defaultSound];

    UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:[[NSUUID UUID] UUIDString]
                                                                          content:content
                                                                          trigger:nil];
    [[UNUserNotificationCenter currentNotificationCenter] addNotificationRequest:request withCompletionHandler:nil];
}

// 应用生命周期管理：后台时停止推送，前台时恢复推送
- (void)applicationDidEnterBackground {
    [self stopPolling];
    [self stopWebSocket];
}

- (void)applicationDidBecomeActive {
    if (self.pollingTimer) [self startPollingWithHandler:self.messageHandler];
    if (self.webSocketTimer) [self startWebSocketWithHandler:self.messageHandler];
}

@end

// C 函数 Hook 实现：替代 MSHookFunction
typedef void *(*DlopenFunc)(const char *, int);
typedef char *(*GetenvFunc)(const char *);
typedef int (*PtraceFunc)(int, pid_t, void *, void *);
typedef int (*SysctlFunc)(int *, u_int, void *, size_t *, void *, size_t);

static DlopenFunc original_dlopen = NULL;
static GetenvFunc original_getenv = NULL;
static PtraceFunc original_ptrace = NULL;
static SysctlFunc original_sysctl = NULL;

void *hooked_dlopen(const char *path, int mode) {
    if (path && (strstr(path, "MobileSubstrate") || strstr(path, "CydiaSubstrate") || strstr(path, "libjailbreak"))) {
        return NULL; // 阻止加载越狱相关动态库
    }
    return original_dlopen ? original_dlopen(path, mode) : dlopen(path, mode); // 调用原始方法
}

char *hooked_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 || strcmp(name, "_SafeMode") == 0 || strcmp(name, "CYDIA") == 0)) {
        return NULL; // 隐藏越狱环境变量
    }
    return original_getenv ? original_getenv(name) : getenv(name); // 调用原始方法
}

int hooked_ptrace(int request, pid_t pid, void *addr, void *data) {
    if (request == PT_DENY_ATTACH) { // 使用定义的 PT_DENY_ATTACH
        return 0; // 伪装成功，绕过检测
    }
    return original_ptrace ? original_ptrace(request, pid, addr, data) : 0; // 调用原始方法或返回默认值
}

int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int result = original_sysctl ? original_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        if (info && (info->kp_proc.p_flag & P_TRACED)) {
            info->kp_proc.p_flag &= ~P_TRACED; // 清除被跟踪标志
        }
    }
    return result;
}

// 反越狱和反调试初始化
__attribute__((constructor)) static void initializeAntiJailbreakAndAntiDebug() {
    // Hook dlopen
    void *dlopen_ptr = dlsym(RTLD_DEFAULT, "dlopen");
    if (dlopen_ptr) {
        original_dlopen = (DlopenFunc)dlopen_ptr;
        *(void **)&dlopen = (void *)hooked_dlopen; // 直接替换函数指针
    }

    // Hook getenv
    void *getenv_ptr = dlsym(RTLD_DEFAULT, "getenv");
    if (getenv_ptr) {
        original_getenv = (GetenvFunc)getenv_ptr;
        *(void **)&getenv = (void *)hooked_getenv; // 直接替换函数指针
    }

    // Hook ptrace
    void *ptrace_ptr = dlsym(RTLD_DEFAULT, "ptrace");
    if (ptrace_ptr) {
        original_ptrace = (PtraceFunc)ptrace_ptr;
    }

    // Hook sysctl
    void *sysctl_ptr = dlsym(RTLD_DEFAULT, "sysctl");
    if (sysctl_ptr) {
        original_sysctl = (SysctlFunc)sysctl_ptr;
        *(void **)&sysctl = (void *)hooked_sysctl; // 直接替换函数指针
    }
}

// 动态库初始化函数：程序入口
__attribute__((constructor)) static void initialize() {
    // 初始化反越狱和反调试保护
    initializeAntiJailbreakAndAntiDebug();

    // 检查调试器
    if (original_ptrace && original_ptrace(PT_DENY_ATTACH, 0, 0, 0) != 0) { // 使用动态加载的 ptrace
        exit(1); // 检测到调试器，退出程序
    }

    // 初始化推送管理器
    PushManager *manager = [PushManager sharedManager];
    static dispatch_once_t onceToken = 0; // 使用 dispatch_once_t 类型
    dispatch_once(&onceToken, ^{
        Class swiftClass = NSClassFromString(@"_TtC12MMHBBackPush32TD5YEPPZuSyJkUIwkTviqXCaqNN4FZIk");
        if (swiftClass) {
            id instance = [[swiftClass alloc] init];
            NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:[swiftClass instanceMethodSignatureForSelector:@selector(JyN1nQrqb3jujX3Do6eC3j07PV1Vz6H4:)]];
            [invocation setSelector:@selector(JyN1nQrqb3jujX3Do6eC3j07PV1Vz6H4:)];
            [invocation setTarget:instance];
            NSData *dummyData = [@"test" dataUsingEncoding:NSUTF8StringEncoding];
            [invocation setArgument:&dummyData atIndex:2];
            [invocation invoke];
        }
    });

    // 请求通知权限
    [[UNUserNotificationCenter currentNotificationCenter] requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound)
                                                                         completionHandler:^(BOOL granted, NSError *error) {
        // 无日志输出，直接处理权限
    }];

    // 启动模拟推送
    [manager startPollingWithHandler:^(id message) {
        // 无日志输出，直接处理消息
    }];
    [manager startWebSocketWithHandler:^(id message) {
        // 无日志输出，直接处理消息
    }];
}