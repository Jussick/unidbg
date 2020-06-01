#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

typedef NSString *NSNotificationName;
const NSNotificationName UIApplicationDidReceiveMemoryWarningNotification = @"UIApplicationDidReceiveMemoryWarningNotification";
const NSNotificationName UIApplicationDidEnterBackgroundNotification = @"UIApplicationDidEnterBackgroundNotification";
const NSNotificationName UIApplicationDidBecomeActiveNotification = @"UIApplicationDidBecomeActiveNotification";
const NSNotificationName UIApplicationWillEnterForegroundNotification = @"UIApplicationWillEnterForegroundNotification";
const NSNotificationName UIApplicationWillResignActiveNotification = @"UIApplicationWillResignActiveNotification";
const NSNotificationName UIApplicationWillTerminateNotification = @"UIApplicationWillTerminateNotification";
const NSNotificationName UIApplicationDidFinishLaunchingNotification = @"UIApplicationDidFinishLaunchingNotification";
const NSNotificationName UIApplicationDidChangeStatusBarOrientationNotification = @"UIApplicationDidChangeStatusBarOrientationNotification";
const NSNotificationName UIApplicationDidChangeStatusBarFrameNotification = @"UIApplicationDidChangeStatusBarFrameNotification";

typedef CGFloat UIWindowLevel;
const UIWindowLevel UIWindowLevelNormal = 0.0;

typedef double NSTimeInterval;
const NSTimeInterval UIApplicationBackgroundFetchIntervalMinimum = 0.0;

typedef enum UIApplicationState : NSInteger {
    UIApplicationStateActive,
    UIApplicationStateInactive,
    UIApplicationStateBackground
} UIApplicationState;

@interface UIColor : NSObject
@end

@interface UIResponder : NSObject
@end

@interface UIView : UIResponder
@property(nonatomic) BOOL accessibilityViewIsModal;
@property(nonatomic, retain) UIColor *backgroundColor;
@property(nonatomic) CGRect frame;
- (id)initWithFrame:(CGRect)rect;
- (void)setAccessibilityViewIsModal:(BOOL)flag;
@end

@interface UIWindow : UIView
@property(nonatomic) UIWindowLevel windowLevel;
- (void)makeKeyAndVisible;
@end

typedef enum UIInterfaceOrientation : NSInteger {
    UIInterfaceOrientationUnknown,
    UIInterfaceOrientationPortrait,
} UIInterfaceOrientation;

typedef enum UIStatusBarStyle : NSInteger {
    UIStatusBarStyleDefault,
} UIStatusBarStyle;

@interface UIApplication : NSObject

@property(nonatomic, getter=isStatusBarHidden) BOOL statusBarHidden;
@property(nonatomic) UIStatusBarStyle statusBarStyle;

+ (UIApplication *)sharedApplication;

- (id)delegate;

- (UIApplicationState)applicationState;

- (UIInterfaceOrientation)statusBarOrientation;

- (CGRect)statusBarFrame;

- (void)setMinimumBackgroundFetchInterval:(NSTimeInterval)minimumBackgroundFetchInterval;

- (NSArray *)windows;

@end

@protocol UIApplicationDelegate<NSObject>
- (UIWindow *)window;
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions;
@end

@interface MyUIApplicationDelegate <UIApplicationDelegate> : NSObject
- (id) m_appViewControllerMgr;
@end

typedef enum UIDeviceBatteryState : NSInteger {
  UIDeviceBatteryStateUnknown,
  UIDeviceBatteryStateUnplugged,
  UIDeviceBatteryStateCharging,
  UIDeviceBatteryStateFull
} UIDeviceBatteryState;

@interface UIDevice : NSObject

@property(nonatomic, getter=isBatteryMonitoringEnabled) BOOL batteryMonitoringEnabled;

+ (UIDevice *)currentDevice;

- (NSString *)systemVersion;
- (NSString *)model;
- (NSUUID *)identifierForVendor;
- (NSString *)systemName;
- (NSString *)name;

- (UIDeviceBatteryState)batteryState;

@end

@interface NSString (Number)
- (unsigned int)unsignedIntValue;
@end

@interface UIViewController : NSObject
@end

@interface UIScreen : NSObject
+ (UIScreen *)mainScreen;
- (CGRect)bounds;
- (CGFloat)scale;
@end
