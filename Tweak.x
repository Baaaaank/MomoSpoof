// MomoSpoof — 设备身份重置（陌陌 / com.immomo.momo）
// 环境：iOS 14 / arm64 / TrollStore + TrollFools 注入
// 不依赖 CydiaSubstrate，未越狱环境可直接加载
// 依赖：fishhook.c / fishhook.h（构建脚本自动下载）
//
// 目标：让服务端认为这是一台"全新的设备"
//   1) 换 IDFV / IDFA / 机型 / 设备名
//   2) 首次启动时让 keychain 里的旧设备 ID 读不到 → App 重新生成
//   3) 屏蔽越狱 / 巨魔常见检测点

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <unistd.h>
#import <string.h>

#import "fishhook.h"

// ==================== 配置区（改这里） ====================
// 机型：iPhone13,4 = iPhone 12 Pro Max。必须是 iOS 14 时代存在的机型，
// 否则"iPhone 15 跑 iOS 14"本身就是异常特征。
static const char *kFakeMachine = "iPhone13,4";

// 设备名
static NSString *const kFakeDeviceName = @"iPhone";

// IDFV：每次需要"换新机"时改这里（随便生成一个新 UUID 即可）
static NSString *const kFakeIDFV = @"9F3A1C2E-8B4D-4E7A-9C11-2D5E7F9A0B31";

// IDFA
static NSString *const kFakeIDFA = @"6C2B4D8E-1A3F-4B5C-8D7E-9F0A1B2C3D4E";

// 是否重置 keychain 里的设备 ID（只在首次启动生效一次）
// 注意：会让陌陌掉登录，需要重新登录
static BOOL const kResetKeychainOnce = YES;

// 是否屏蔽越狱 / 巨魔 / Cydia 相关检测
static BOOL const kHideJailbreak = YES;
// =========================================================

static NSString *const kResetFlagKey = @"MomoSpoofDidReset_v1";

#pragma mark - ObjC 方法替换

static IMP replace_method(Class cls, SEL sel, IMP newImp) {
    if (!cls || !sel || !newImp) return NULL;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NULL;
    IMP old = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return old;
}

#pragma mark - 1. sysctlbyname: hw.machine

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                             void *newp, size_t newlen) {
    if (name && oldp && oldlenp && strcmp(name, "hw.machine") == 0) {
        size_t need = strlen(kFakeMachine) + 1;
        if (*oldlenp >= need) {
            memcpy(oldp, kFakeMachine, need);
            *oldlenp = need;
            return 0;
        }
        *oldlenp = need;
        return -1;
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

#pragma mark - 2. uname

static int (*orig_uname)(struct utsname *);

static int hook_uname(struct utsname *buf) {
    int r = orig_uname(buf);
    if (r == 0 && buf) {
        strncpy(buf->machine, kFakeMachine, sizeof(buf->machine) - 1);
        buf->machine[sizeof(buf->machine) - 1] = '\0';
    }
    return r;
}

#pragma mark - 3. UIDevice / IDFA

static id hook_idfv(id self, SEL _cmd) {
    static NSUUID *u = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ u = [[NSUUID alloc] initWithUUIDString:kFakeIDFV]; });
    return u;
}

static NSString *hook_device_name(id self, SEL _cmd) { return kFakeDeviceName; }
static NSString *hook_device_model(id self, SEL _cmd) { return @"iPhone"; }

static id hook_idfa(id self, SEL _cmd) {
    static NSUUID *u = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ u = [[NSUUID alloc] initWithUUIDString:kFakeIDFA]; });
    return u;
}

#pragma mark - 4. URL scheme 探测（巨魔 / 越狱）

static BOOL (*orig_canOpenURL)(id, SEL, NSURL *);

static BOOL hook_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (kHideJailbreak && url) {
        NSString *s = url.absoluteString.lowercaseString;
        if (!s) return NO;
        static NSString *const prefixes[] = { @"apple-magnifier://", @"cydia://",
                                              @"sileo://", @"zbra://", @"filza://" };
        size_t n = sizeof(prefixes) / sizeof(prefixes[0]);
        for (size_t i = 0; i < n; i++) {
            if ([s hasPrefix:prefixes[i]]) return NO;
        }
    }
    return orig_canOpenURL ? orig_canOpenURL(self, _cmd, url) : NO;
}

#pragma mark - 5. 越狱文件检测绕过

static const char *kJailbreakPaths[] = {
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Library/MobileSubstrate",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/bin/bash",
    "/etc/apt",
    "/private/var/lib/apt",
    "/usr/libexec/cydia",
    "/var/jb",
    NULL
};

static BOOL is_jailbreak_path(const char *path) {
    if (!kHideJailbreak || !path) return NO;
    for (int i = 0; kJailbreakPaths[i]; i++) {
        if (strcmp(path, kJailbreakPaths[i]) == 0) return YES;
    }
    return NO;
}

static int (*orig_access)(const char *, int);
static int hook_access(const char *path, int mode) {
    if (is_jailbreak_path(path)) return -1;
    return orig_access(path, mode);
}

static int (*orig_stat)(const char *, struct stat *);
static int hook_stat(const char *path, struct stat *buf) {
    if (is_jailbreak_path(path)) return -1;
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hook_lstat(const char *path, struct stat *buf) {
    if (is_jailbreak_path(path)) return -1;
    return orig_lstat(path, buf);
}

#pragma mark - 6. keychain 设备 ID 重置（只做一次）

static NSArray<NSString *> *token_account_keys(void) {
    static NSArray<NSString *> *keys;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keys = @[ @"token", @"session", @"login", @"auth",
                  @"password", @"passwd", @"credential", @"user" ];
    });
    return keys;
}

static BOOL has_token_keyword(CFDictionaryRef dict) {
    if (!dict) return NO;
    CFTypeRef acc = CFDictionaryGetValue(dict, kSecAttrAccount);
    if (!acc || CFGetTypeID(acc) != CFStringGetTypeID()) return NO;
    NSString *s = [(__bridge NSString *)acc lowercaseString];
    if (!s) return NO;
    for (NSString *k in token_account_keys()) {
        if ([s containsString:k]) return YES;
    }
    return NO;
}

static BOOL is_generic_password(CFDictionaryRef dict) {
    if (!dict) return NO;
    CFTypeRef cls = CFDictionaryGetValue(dict, kSecClass);
    return cls && CFGetTypeID(cls) == CFStringGetTypeID()
           && CFEqual(cls, kSecClassGenericPassword);
}

// 是否处于"本次启动要重置一次"的状态
static BOOL reset_this_launch(void) {
    static BOOL evaluated = NO;
    static BOOL should = NO;
    if (evaluated) return should;
    evaluated = YES;
    if (!kResetKeychainOnce) return NO;
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    if (![d boolForKey:kResetFlagKey]) {
        [d setBool:YES forKey:kResetFlagKey];
        [d synchronize];
        should = YES;
        NSLog(@"[MomoSpoof] keychain reset armed for this launch");
    }
    return should;
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);

static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (reset_this_launch() && is_generic_password(query) && !has_token_keyword(query)) {
        if (result) *result = NULL;
        return errSecItemNotFound;
    }
    return orig_SecItemCopyMatching(query, result);
}

static OSStatus hook_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *result) {
    if (reset_this_launch() && is_generic_password(attrs) && !has_token_keyword(attrs)) {
        SecItemDelete(attrs); // 先删旧条目，避免 duplicate 导致写入失败
    }
    return orig_SecItemAdd(attrs, result);
}

#pragma mark - 初始化

// 遍历 App 内所有已加载/后加载的二进制做符号重绑。
// 只 rebind 主二进制会漏掉陌陌自己的 framework，keychain 就 hook 不到。
static struct rebinding g_rb[] = {
    {"sysctlbyname",        (void *)hook_sysctlbyname,        (void **)&orig_sysctlbyname},
    {"uname",               (void *)hook_uname,               (void **)&orig_uname},
    {"access",              (void *)hook_access,              (void **)&orig_access},
    {"stat",                (void *)hook_stat,                (void **)&orig_stat},
    {"lstat",               (void *)hook_lstat,               (void **)&orig_lstat},
    {"SecItemCopyMatching", (void *)hook_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
    {"SecItemAdd",          (void *)hook_SecItemAdd,          (void **)&orig_SecItemAdd},
};
static const size_t g_rb_count = sizeof(g_rb) / sizeof(g_rb[0]);

static const void *g_seen[256];
static int g_seen_count = 0;

static void on_image_added(const struct mach_header *mh, intptr_t slide) {
    if (!mh) return;
    for (int i = 0; i < g_seen_count; i++) {
        if (g_seen[i] == mh) return; // 防重复 rebind 造成递归
    }
    if (g_seen_count < 256) g_seen[g_seen_count++] = mh;

    Dl_info info;
    if (dladdr(mh, &info) == 0 || !info.dli_fname) return;
    const char *path = info.dli_fname;
    // 只处理 App bundle 内的二进制，跳过 /usr/lib、/System
    if (strstr(path, ".app/") == NULL) return;

    rebind_symbols_image((void *)mh, slide, g_rb, g_rb_count);
}

__attribute__((constructor))
static void momospoof_init(void) {
    Class dev = [UIDevice class];
    replace_method(dev, @selector(identifierForVendor), (IMP)hook_idfv);
    replace_method(dev, @selector(name), (IMP)hook_device_name);
    replace_method(dev, @selector(model), (IMP)hook_device_model);

    Class asim = objc_getClass("ASIdentifierManager");
    if (asim) {
        replace_method(asim, @selector(advertisingIdentifier), (IMP)hook_idfa);
    }

    Class app = [UIApplication class];
    orig_canOpenURL = (BOOL (*)(id, SEL, NSURL *))replace_method(app, @selector(canOpenURL:), (IMP)hook_canOpenURL);

    // dyld 会立刻对已加载的 image 回调一次，后续加载的也会回调
    _dyld_register_func_for_add_image(on_image_added);

    NSLog(@"[MomoSpoof] loaded machine=%s idfv=%@", kFakeMachine, kFakeIDFV);
}
