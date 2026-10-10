#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <substrate.h>
#import <dlfcn.h>

// The tweak keeps the vendor dylib untouched. It creates the expected 64-char
// activation payload only when no usable payload is already present, then
// overrides signature verification only when the caller is SwipeDeck.dylib.
static Boolean (*SD_origVerify)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef *);
static const char *kActivationPath = "/var/mobile/Library/Preferences/com.zooah.swipedeck/activation.dat";
static const char *kPayload = "1111111111111111111111111111111111111111111111111111111111111111";

static BOOL SD_isSwipeDeckCaller(void) {
    void *ra = __builtin_return_address(0);
    Dl_info info = {0};
    if (ra && dladdr(ra, &info) && info.dli_fname) {
        NSString *path = [NSString stringWithUTF8String:info.dli_fname];
        return [path.lastPathComponent isEqualToString:@"SwipeDeck.dylib"];
    }
    return NO;
}

static Boolean SD_verify(SecKeyRef key, SecKeyAlgorithm alg, CFDataRef signedData,
                         CFDataRef signature, CFErrorRef *error) {
    if (SD_isSwipeDeckCaller()) {
        if (error) *error = NULL;
        return true;
    }
    return SD_origVerify ? SD_origVerify(key, alg, signedData, signature, error) : false;
}

static void SD_seedActivationStore(void) {
    NSString *path = [NSString stringWithUTF8String:kActivationPath];
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *dir = [path stringByDeletingLastPathComponent];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSData *old = [NSData dataWithContentsOfFile:path];
    if (old.length == 64) return;
    NSData *payload = [[NSString stringWithUTF8String:kPayload] dataUsingEncoding:NSUTF8StringEncoding];
    [payload writeToFile:path atomically:YES];
}

static void SD_install(void) {
    SD_seedActivationStore();
    void *p = dlsym(RTLD_DEFAULT, "SecKeyVerifySignature");
    if (p && !SD_origVerify) MSHookFunction(p, (void *)SD_verify, (void **)&SD_origVerify);
}

%ctor {
    @autoreleasepool {
        // SwipeDeck is normally loaded before this tweak. The retries also
        // cover SpringBoard/Preferences load-order changes after updates.
        SD_install();
        for (NSUInteger i = 1; i <= 5; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 250) * NSEC_PER_MSEC),
                           dispatch_get_main_queue(), ^{ SD_install(); });
        }
    }
}
