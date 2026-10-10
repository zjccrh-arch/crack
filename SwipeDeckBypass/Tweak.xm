#import <Foundation/Foundation.h>
#import <substrate.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <notify.h>
#import <sys/stat.h>
#import <unistd.h>
#import "VerifierPattern.h"

static const struct mach_header *SDInstalled[2];
static void *SDOriginal[2];
static uint64_t SDVerifier(uint64_t deviceValue, id signature) {
    (void)deviceValue;
    (void)signature;
    return 1;
}

static NSString *SDStoreForImage(NSString *path) {
    // Derive the bootstrap from the loaded image, never a jbroot UUID.
    NSArray<NSString *> *suffixes = @[
        @"/usr/lib/TweakInject/SwipeDeck.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries/SwipeDeck.dylib",
        @"/Library/PreferenceBundles/SwipeDeckPrefs.bundle/SwipeDeckPrefs"
    ];
    for (NSString *suffix in suffixes) {
        if ([path hasSuffix:suffix]) {
            NSString *root = [path substringToIndex:path.length - suffix.length];
            return [root stringByAppendingString:
                @"/var/mobile/Library/Preferences/com.zooah.swipedeck"];
        }
    }
    return nil;
}

static BOOL SDSeed(NSString *store) {
    if (!store) return NO;
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *path = [store stringByAppendingPathComponent:@"activation.dat"];
    if ([fm fileExistsAtPath:path]) return YES;
    NSError *error = nil;
    if (![fm createDirectoryAtPath:store withIntermediateDirectories:YES
            attributes:nil error:&error]) {
        NSLog(@"[SwipeDeckBypass 1.1.0] mkdir failed: %@", error);
        return NO;
    }
    NSData *seed = [@"1111111111111111111111111111111111111111111111111111111111111111"
                    dataUsingEncoding:NSUTF8StringEncoding];
    BOOL ok = [seed writeToFile:path
                   options:NSDataWritingAtomic | NSDataWritingWithoutOverwriting
                     error:&error];
    if (ok) chmod(path.fileSystemRepresentation, 0600);
    NSLog(@"[SwipeDeckBypass 1.1.0] seed=%d store=%@ error=%@", ok, store, error);
    return ok || [fm fileExistsAtPath:path];
}

static void SDInstallImage(const struct mach_header *header, intptr_t slide) {
    if (!header || header->magic != MH_MAGIC_64) return;
    Dl_info info = {};
    if (!dladdr(header, &info) || !info.dli_fname) return;
    NSString *path = [NSString stringWithUTF8String:info.dli_fname];
    NSString *name = path.lastPathComponent;
    int slot = [name isEqualToString:@"SwipeDeck.dylib"] ? 0
             : [name isEqualToString:@"SwipeDeckPrefs"] ? 1 : -1;
    if (slot < 0 || SDInstalled[slot]) return;
    NSString *store = SDStoreForImage(path);
    if (!store) return;
    const struct section_64 *section = getsectbynamefromheader_64(
        (const struct mach_header_64 *)header, "__TEXT", "__text");
    if (!section || !section->size || section->size > 64 * 1024 * 1024) return;
    const uint8_t *code = (const uint8_t *)(section->addr + slide);
    size_t entry = 0;
    size_t matches = SDFindVerifier(code, (size_t)section->size, &entry);
    if (matches != 1) {
        NSLog(@"[SwipeDeckBypass 1.1.0] NOT INSTALLED image=%@ matches=%zu; compatibility check failed", name, matches);
        return;
    }
    if (!SDSeed(store)) return;
    MSHookFunction((void *)(code + entry), (void *)SDVerifier, &SDOriginal[slot]);
    if (!SDOriginal[slot]) {
        NSLog(@"[SwipeDeckBypass 1.1.0] hook failed image=%@", name);
        return;
    }
    SDInstalled[slot] = header;
    NSString *line = [NSString stringWithFormat:
        @"v1.1.0 pid=%d image=%@ uniqueVerifier=1 hookInstalled=1 initializationPreserved=1\n",
        getpid(), name];
    [line writeToFile:[store stringByAppendingPathComponent:
        [NSString stringWithFormat:@"bypass-%@.log", name]]
        atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"[SwipeDeckBypass] %@", line);
    dispatch_async(dispatch_get_main_queue(), ^{
        notify_post("com.zooah.swipedeck.activationChanged");
        [[NSNotificationCenter defaultCenter]
            postNotificationName:@"com.zooah.swipedeck.activationChanged" object:nil];
    });
}

static void SDImageAdded(const struct mach_header *header, intptr_t slide) {
    // Preferences loads its bundle later. No Foundation work under dyld lock.
    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool { SDInstallImage(header, slide); }
    });
}

%ctor {
    @autoreleasepool {
        NSString *process = NSProcessInfo.processInfo.processName;
        if (![process isEqualToString:@"SpringBoard"] &&
            ![process isEqualToString:@"Preferences"]) return;
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            SDInstallImage(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
        _dyld_register_func_for_add_image(SDImageAdded);
    }
}
