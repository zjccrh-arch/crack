#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <substrate.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <stdio.h>
#import <unistd.h>
#import <string.h>

// The tweak keeps the vendor dylib untouched. It creates the expected 64-char
// activation payload only when no usable payload is already present, then
// overrides signature verification only when the caller is SwipeDeck.dylib.
static Boolean (*SD_origVerify)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef *);
static const char *kActivationPath = "/var/mobile/Library/Preferences/com.zooah.swipedeck/activation.dat";
static const char *kPayload = "1111111111111111111111111111111111111111111111111111111111111111";
static const char *kActivationNotification = "com.zooah.swipedeck.activationChanged";

static void SD_log(NSString *message) {
    NSString *path = @"/var/mobile/Library/Preferences/com.zooah.swipedeck/bypass-diagnostic.log";
    FILE *fp = fopen(path.fileSystemRepresentation, "a");
    if (fp) {
        fprintf(fp, "[%d] %s\n", getpid(), message.UTF8String);
        fclose(fp);
    }
}

static BOOL SD_isSwipeDeckCaller(void *ra) {
    Dl_info info = {0};
    if (ra && dladdr(ra, &info) && info.dli_fname) {
        const char *base = strrchr(info.dli_fname, '/');
        return strcmp(base ? base + 1 : info.dli_fname, "SwipeDeck.dylib") == 0;
    }
    return NO;
}

static Boolean SD_verify(SecKeyRef key, SecKeyAlgorithm alg, CFDataRef signedData,
                         CFDataRef signature, CFErrorRef *error) {
    if (SD_isSwipeDeckCaller(__builtin_return_address(0))) {
        static unsigned logged = 0;
        if (logged++ < 8) SD_log([NSString stringWithFormat:
            @"signature hook HIT data=%ld DER=%ld", (long)CFDataGetLength(signedData),
            (long)CFDataGetLength(signature)]);
        if (error) *error = NULL;
        return true;
    }
    return SD_origVerify ? SD_origVerify(key, alg, signedData, signature, error) : false;
}

static void SD_seedActivationStore(void) {
    NSString *path = [NSString stringWithUTF8String:kActivationPath];
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *dir = [path stringByDeletingLastPathComponent];
    NSError *error = nil;
    BOOL created = [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&error];
    NSData *old = [NSData dataWithContentsOfFile:path];
    if (old.length == 64) {
        SD_log([NSString stringWithFormat:@"seed existing length=64 path=%@", path]);
        return;
    }
    NSData *payload = [[NSString stringWithUTF8String:kPayload] dataUsingEncoding:NSUTF8StringEncoding];
    BOOL written = [payload writeToFile:path options:NSDataWritingAtomic error:&error];
    SD_log([NSString stringWithFormat:@"seed mkdir=%d write=%d old=%lu path=%@ error=%@",
        created, written, (unsigned long)old.length, path, error]);
}

static void SD_postActivationChanged(void) {
    static int (*notify_post_fn)(const char *) = NULL;
    static void *notify_handle = NULL;
    if (!notify_post_fn) {
        notify_post_fn = (int (*)(const char *))dlsym(RTLD_DEFAULT, "notify_post");
        if (!notify_post_fn) {
            notify_handle = dlopen("/usr/lib/system/libsystem_notify.dylib", RTLD_LAZY);
            if (notify_handle) {
                notify_post_fn = (int (*)(const char *))dlsym(notify_handle, "notify_post");
            }
        }
    }
    int rc = notify_post_fn ? notify_post_fn(kActivationNotification) : -1;
    [[NSNotificationCenter defaultCenter]
        postNotificationName:[NSString stringWithUTF8String:kActivationNotification]
                      object:nil];
    SD_log([NSString stringWithFormat:@"activationChanged posted notify_rc=%d local=%@",
        rc, notify_post_fn ? @"yes" : @"no"]);
}

static void SD_scheduleActivationChanged(void) {
    dispatch_queue_t q = dispatch_get_main_queue();
    const int delays[] = {250, 1000, 3000, 10000};
    for (NSUInteger i = 0; i < sizeof(delays) / sizeof(delays[0]); i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                     (int64_t)delays[i] * NSEC_PER_MSEC), q, ^{
            SD_seedActivationStore();
            SD_postActivationChanged();
        });
    }
}

static id (*SD_origRead)(id, SEL, NSString *, NSUInteger, NSError **);
static id SD_read(id cls, SEL sel, NSString *path, NSUInteger options, NSError **error) {
    BOOL target = [path.lastPathComponent isEqualToString:@"activation.dat"];
    id result = SD_origRead(cls, sel, path, options, error);
    if (target) {
        SD_log([NSString stringWithFormat:@"vendor read path=%@ length=%lu error=%@",
            path, (unsigned long)[result length], error ? *error : nil]);
        if ([result length] != 64) {
            NSData *payload = [[NSString stringWithUTF8String:kPayload]
                dataUsingEncoding:NSUTF8StringEncoding];
            if (error) *error = nil;
            SD_log(@"vendor read fallback supplied 64-byte payload");
            return payload;
        }
    }
    return result;
}

static void SD_install(void) {
    SD_seedActivationStore();
    void *p = dlsym(RTLD_DEFAULT, "SecKeyVerifySignature");
    if (p && !SD_origVerify) {
        MSHookFunction(p, (void *)SD_verify, (void **)&SD_origVerify);
        SD_log([NSString stringWithFormat:@"verify installed=%d", SD_origVerify != NULL]);
    }
}

%ctor {
    @autoreleasepool {
        // SwipeDeck is normally loaded before this tweak. The retries also
        // cover SpringBoard/Preferences load-order changes after updates.
        SD_seedActivationStore();
        SD_log(@"ctor v1.0.1");
        Class cls = object_getClass(NSData.class);
        MSHookMessageEx(cls, @selector(dataWithContentsOfFile:options:error:),
                       (IMP)SD_read, (IMP *)&SD_origRead);
        SD_log([NSString stringWithFormat:@"read observer installed=%d", SD_origRead != NULL]);
        SD_install();
        SD_postActivationChanged();
        SD_scheduleActivationChanged();
        for (NSUInteger i = 1; i <= 5; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 250) * NSEC_PER_MSEC),
                           dispatch_get_main_queue(), ^{ SD_install(); });
        }
    }
}
