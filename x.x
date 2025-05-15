// 作者：pxx917144686

// ============== 头文件 ==============
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <UserNotifications/UserNotifications.h>
#include <objc/runtime.h>
#include <CommonCrypto/CommonCryptor.h>

// 配置类：管理伪装和推送相关配置
@interface HookConfig : NSObject
@property (nonatomic, strong) NSDictionary *fakeInfoPlist;
@property (nonatomic, assign) NSTimeInterval minPollingInterval;
@property (nonatomic, assign) NSTimeInterval maxPollingInterval;
@property (nonatomic, strong) NSData *encryptionKey;
+ (instancetype)sharedConfig;
@end

// NSBundle 的 Category 接口扩展
@interface NSBundle (Hook)
+ (void)zcxd_startHook;
+ (void)zcxd_actionHook;
- (BOOL)shouldHookAt:(NSString *)path;
- (NSString *)zcxd_bundleIdentifier;
- (NSDictionary *)zcxd_infoDictionary;
- (id)zcxd_objectForInfoDictionaryKey:(NSString *)key;
- (BOOL)hook_fileExistsAtPath:(NSString *)path;
- (BOOL)hook_fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir;
@end

// 推送管理类接口
@interface PushManager : NSObject
@property (nonatomic, strong) NSTimer *pollingTimer;
@property (nonatomic, strong) NSTimer *webSocketTimer;
@property (nonatomic, assign) NSTimeInterval currentPollingInterval;
@property (nonatomic, copy) void (^messageHandler)(id message);
@property (nonatomic, assign) NSTimeInterval lastHeartbeatTime;
+ (instancetype)sharedManager;
- (void)startPollingWithHandler:(void (^)(id message))handler;
- (void)stopPolling;
- (void)startWebSocketWithHandler:(void (^)(id message))handler;
- (void)stopWebSocket;
- (void)showLocalNotificationWithMessage:(NSString *)message;
@end

// 全局变量
static dispatch_once_t zcxd_startHook_onceToken = 0;
static IMP originalBundleIdentifierIMP = NULL;
static IMP originalInfoDictionaryIMP = NULL;
static IMP originalObjectForInfoDictionaryKeyIMP = NULL;
static IMP originalFileExistsAtPathIMP = NULL;
static IMP originalFileExistsAtPathIsDirectoryIMP = NULL;

// 获取调用者路径
static NSString *getCallerPath() {
    return [[NSBundle mainBundle] executablePath];
}

// HookConfig 实现
@implementation HookConfig

+ (instancetype)sharedConfig {
    static HookConfig *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
        sharedInstance.fakeInfoPlist = @{@"CFBundleIdentifier": @"com.tencent.xin", @"CFBundleName": @"WeChat"};
        sharedInstance.minPollingInterval = 5.0;
        sharedInstance.maxPollingInterval = 15.0;
        sharedInstance.encryptionKey = [sharedInstance generateEncryptionKey];
    });
    return sharedInstance;
}

- (NSData *)generateEncryptionKey {
    NSMutableData *key = [NSMutableData dataWithLength:kCCKeySizeAES256];
    (void)SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES256, key.mutableBytes);
    return key;
}

@end

// NSBundle 的 Category 实现
@implementation NSBundle (Hook)

+ (void)load {
    [self zcxd_startHook];
}

+ (void)zcxd_startHook {
    dispatch_once(&zcxd_startHook_onceToken, ^{
        [self zcxd_actionHook];
    });
}

+ (void)zcxd_actionHook {
    Method origMethod = class_getInstanceMethod(self, @selector(bundleIdentifier));
    Method hookMethod = class_getInstanceMethod(self, @selector(zcxd_bundleIdentifier));
    originalBundleIdentifierIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);

    origMethod = class_getInstanceMethod(self, @selector(infoDictionary));
    hookMethod = class_getInstanceMethod(self, @selector(zcxd_infoDictionary));
    originalInfoDictionaryIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);

    origMethod = class_getInstanceMethod(self, @selector(objectForInfoDictionaryKey:));
    hookMethod = class_getInstanceMethod(self, @selector(zcxd_objectForInfoDictionaryKey:));
    originalObjectForInfoDictionaryKeyIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);

    origMethod = class_getInstanceMethod(objc_getClass("NSFileManager"), @selector(fileExistsAtPath:));
    hookMethod = class_getInstanceMethod(self, @selector(hook_fileExistsAtPath:));
    originalFileExistsAtPathIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);

    origMethod = class_getInstanceMethod(objc_getClass("NSFileManager"), @selector(fileExistsAtPath:isDirectory:));
    hookMethod = class_getInstanceMethod(self, @selector(hook_fileExistsAtPath:isDirectory:));
    originalFileExistsAtPathIsDirectoryIMP = method_getImplementation(origMethod);
    method_exchangeImplementations(origMethod, hookMethod);
}

- (BOOL)shouldHookAt:(NSString *)path {
    if (!path) return NO;
    NSString *mainBundlePath = [[NSBundle mainBundle] bundlePath];
    if ([path hasPrefix:mainBundlePath]) {
        return YES;
    }
    return NO;
}

- (NSString *)zcxd_bundleIdentifier {
    NSString *callerPath = getCallerPath();
    if (self == [NSBundle mainBundle] && [self shouldHookAt:callerPath]) {
        return [HookConfig sharedConfig].fakeInfoPlist[@"CFBundleIdentifier"];
    }
    return ((NSString * (*)(id, SEL))originalBundleIdentifierIMP)(self, @selector(bundleIdentifier));
}

- (NSDictionary *)zcxd_infoDictionary {
    NSString *callerPath = getCallerPath();
    if (self == [NSBundle mainBundle] && [self shouldHookAt:callerPath]) {
        NSDictionary *origDict = ((NSDictionary * (*)(id, SEL))originalInfoDictionaryIMP)(self, @selector(infoDictionary));
        NSMutableDictionary *dict = [origDict mutableCopy];
        [dict addEntriesFromDictionary:[HookConfig sharedConfig].fakeInfoPlist];
        return dict;
    }
    return ((NSDictionary * (*)(id, SEL))originalInfoDictionaryIMP)(self, @selector(infoDictionary));
}

- (id)zcxd_objectForInfoDictionaryKey:(NSString *)key {
    NSString *callerPath = getCallerPath();
    if (self == [NSBundle mainBundle] && [self shouldHookAt:callerPath]) {
        id fakeValue = [HookConfig sharedConfig].fakeInfoPlist[key];
        if (fakeValue) return fakeValue;
    }
    return ((id (*)(id, SEL, NSString *))originalObjectForInfoDictionaryKeyIMP)(self, @selector(objectForInfoDictionaryKey:), key);
}

- (BOOL)hook_fileExistsAtPath:(NSString *)path {
    return ((BOOL (*)(id, SEL, NSString *))originalFileExistsAtPathIMP)(self, @selector(hook_fileExistsAtPath:), path);
}

- (BOOL)hook_fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir {
    return ((BOOL (*)(id, SEL, NSString *, BOOL *))originalFileExistsAtPathIsDirectoryIMP)(self, @selector(hook_fileExistsAtPath:isDirectory:), path, isDir);
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
        _currentPollingInterval = [HookConfig sharedConfig].minPollingInterval;
        _lastHeartbeatTime = 0;
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

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [self stopPolling];
    [self stopWebSocket];
}

- (void)startPollingWithHandler:(void (^)(id message))handler {
    self.messageHandler = handler;
    [self stopPolling];
    self.currentPollingInterval = [self predictPollingInterval];
    self.pollingTimer = [NSTimer scheduledTimerWithTimeInterval:self.currentPollingInterval
                                                         target:self
                                                       selector:@selector(checkForNewMessages)
                                                       userInfo:nil
                                                        repeats:YES];
}

- (void)stopPolling {
    [self.pollingTimer invalidate];
    self.pollingTimer = nil;
}

- (NSTimeInterval)predictPollingInterval {
    NSTimeInterval minInterval = [HookConfig sharedConfig].minPollingInterval;
    NSTimeInterval maxInterval = [HookConfig sharedConfig].maxPollingInterval;
    return minInterval + arc4random_uniform((uint32_t)(maxInterval - minInterval));
}

- (void)checkForNewMessages {
    NSString *simulatedMessage = [self generateSimulatedMessage];
    NSData *encryptedData = [self encryptMessage:simulatedMessage];
    NSString *decryptedMessage = [self decryptMessage:encryptedData];
    if (decryptedMessage && self.messageHandler) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.messageHandler(decryptedMessage);
            [self showLocalNotificationWithMessage:decryptedMessage];
        });
    }
    self.currentPollingInterval = [self predictPollingInterval];
    [self.pollingTimer setFireDate:[NSDate dateWithTimeIntervalSinceNow:self.currentPollingInterval]];
}

- (void)startWebSocketWithHandler:(void (^)(id message))handler {
    [self stopWebSocket];
    self.messageHandler = handler;
    self.webSocketTimer = [NSTimer scheduledTimerWithTimeInterval:10.0
                                                           target:self
                                                         selector:@selector(simulateWebSocketMessage)
                                                         userInfo:nil
                                                          repeats:YES];
    self.lastHeartbeatTime = [[NSDate date] timeIntervalSince1970];
}

- (void)stopWebSocket {
    [self.webSocketTimer invalidate];
    self.webSocketTimer = nil;
}

- (void)simulateWebSocketMessage {
    NSString *simulatedMessage = [self generateSimulatedMessage];
    NSData *encryptedData = [self encryptMessage:simulatedMessage];
    NSString *decryptedMessage = [self decryptMessage:encryptedData];
    if (decryptedMessage && self.messageHandler) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.messageHandler(decryptedMessage);
            [self showLocalNotificationWithMessage:decryptedMessage];
        });
    }
    [self simulateHeartbeat];
}

- (void)simulateHeartbeat {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - self.lastHeartbeatTime > 30.0) {
        self.lastHeartbeatTime = now;
    }
}

- (NSString *)generateSimulatedMessage {
    NSArray *messages = @[@"pxx！", @"pxx917144686！"];
    return messages[arc4random_uniform((uint32_t)messages.count)];
}

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

- (void)applicationDidEnterBackground {
    [self stopPolling];
    [self stopWebSocket];
}

- (void)applicationDidBecomeActive {
    if (self.pollingTimer) [self startPollingWithHandler:self.messageHandler];
    if (self.webSocketTimer) [self startWebSocketWithHandler:self.messageHandler];
}

@end

// 动态库初始化函数
__attribute__((constructor)) static void initialize() {
    PushManager *manager = [PushManager sharedManager];
    static dispatch_once_t onceToken = 0;
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

    [[UNUserNotificationCenter currentNotificationCenter] requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound)
                                                                         completionHandler:^(BOOL granted, NSError *error) {
    }];

    [manager startPollingWithHandler:^(id message) {
    }];
    [manager startWebSocketWithHandler:^(id message) {
    }];
}