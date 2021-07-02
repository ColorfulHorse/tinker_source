package com.tencent.tinker.loader.hotplug;

import android.content.Context;
import android.os.Build;
import android.os.Handler;

import com.tencent.tinker.loader.app.TinkerApplication;
import com.tencent.tinker.loader.hotplug.handler.AMSInterceptHandler;
import com.tencent.tinker.loader.hotplug.handler.MHMessageHandler;
import com.tencent.tinker.loader.hotplug.handler.PMSInterceptHandler;
import com.tencent.tinker.loader.hotplug.interceptor.HandlerMessageInterceptor;
import com.tencent.tinker.loader.hotplug.interceptor.ServiceBinderInterceptor;
import com.tencent.tinker.loader.hotplug.interceptor.TinkerHackInstrumentation;
import com.tencent.tinker.loader.shareutil.ShareReflectUtil;
import com.tencent.tinker.loader.shareutil.ShareSecurityCheck;
import com.tencent.tinker.loader.shareutil.ShareTinkerLog;

import java.lang.reflect.Field;

/**
 * Created by tangyinsheng on 2017/7/31.
 */

public final class ComponentHotplug {
    private static final String TAG = "Tinker.ComponentHotplug";

    private static volatile boolean sInstalled = false;
    private static ServiceBinderInterceptor sAMSInterceptor;
    private static ServiceBinderInterceptor sPMSInterceptor;
    private static HandlerMessageInterceptor sMHMessageInterceptor;
    private static TinkerHackInstrumentation sTinkerHackInstrumentation;

    public synchronized static void install(TinkerApplication app, ShareSecurityCheck checker) throws UnsupportedEnvironmentException {
        if (!sInstalled) {
            try {
                // 解析inc_component_meta，将xml activity节点解析为ActivityInfo对象并存
                if (IncrementComponentManager.init(app, checker)) {
                    // ServiceManager.getService获取AMS客户端代理对象，然后创建此代理对象的动态代理对象，hook startActivity等方法
                    sAMSInterceptor = new ServiceBinderInterceptor(app, EnvConsts.ACTIVITY_MANAGER_SRVNAME, new AMSInterceptHandler(app));
                    // 同理hook PMS
                    sPMSInterceptor = new ServiceBinderInterceptor(app, EnvConsts.PACKAGE_MANAGER_SRVNAME, new PMSInterceptHandler());
                    sAMSInterceptor.install();
                    sPMSInterceptor.install();

                    if (Build.VERSION.SDK_INT < 27) {
                        // android 8.1以下
                        // ActivityThread.mH
                        final Handler mH = fetchMHInstance(app);
                        // hook ActivityThread.mH，将H.mCallBack替换为MHMessageHandler
                        sMHMessageInterceptor = new HandlerMessageInterceptor(mH, new MHMessageHandler(app));
                        sMHMessageInterceptor.install();
                    } else {
                        // >=8.1 hook ActivityThread.mInstrumentation，把他替换为TinkerHackInstrumentation
                        sTinkerHackInstrumentation = TinkerHackInstrumentation.create(app);
                        sTinkerHackInstrumentation.install();
                    }

                    sInstalled = true;

                    ShareTinkerLog.i(TAG, "installed successfully.");
                }
            } catch (Throwable thr) {
                uninstall();
                throw new UnsupportedEnvironmentException(thr);
            }
        }
    }

    public synchronized static void ensureComponentHotplugInstalled(TinkerApplication app) throws UnsupportedEnvironmentException {
        // Some environments may reset AMS, PMS and mH，which cause component hotplug feature
        // being unavailable. So we reinstall them here.
        if (sInstalled) {
            try {
                sAMSInterceptor.install();
                sPMSInterceptor.install();
                if (Build.VERSION.SDK_INT < 27) {
                    sMHMessageInterceptor.install();
                } else {
                    sTinkerHackInstrumentation.install();
                }
            } catch (Throwable thr) {
                uninstall();
                throw new UnsupportedEnvironmentException(thr);
            }
        } else {
            ShareTinkerLog.i(TAG, "method install() is not invoked, ignore ensuring operations.");
        }
    }

    private static Handler fetchMHInstance(Context context) {
        final Object activityThread = ShareReflectUtil.getActivityThread(context, null);
        if (activityThread == null) {
            throw new IllegalStateException("failed to fetch instance of ActivityThread.");
        }
        try {
            final Field mHField = ShareReflectUtil.findField(activityThread, "mH");
            final Handler mH = (Handler) mHField.get(activityThread);
            return mH;
        } catch (Throwable thr) {
            throw new IllegalStateException(thr);
        }
    }

    public synchronized static void uninstall()  {
        if (sInstalled) {
            try {
                sAMSInterceptor.uninstall();
                sPMSInterceptor.uninstall();
                if (Build.VERSION.SDK_INT < 27) {
                    sMHMessageInterceptor.uninstall();
                } else {
                    sTinkerHackInstrumentation.uninstall();
                }
            } catch (Throwable thr) {
                ShareTinkerLog.e(TAG, "exception when uninstall.", thr);
            }

            sInstalled = false;
        }
    }

    private ComponentHotplug() {
        throw new UnsupportedOperationException();
    }
}
