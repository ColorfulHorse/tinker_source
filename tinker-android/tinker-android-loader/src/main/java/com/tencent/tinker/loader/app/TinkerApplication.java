/*
 * Tencent is pleased to support the open source community by making Tinker available.
 *
 * Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.
 *
 * Licensed under the BSD 3-Clause License (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 * https://opensource.org/licenses/BSD-3-Clause
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.tencent.tinker.loader.app;

import android.annotation.TargetApi;
import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.content.res.AssetManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Handler;
import android.os.SystemClock;

import com.tencent.tinker.anno.Keep;
import com.tencent.tinker.loader.TinkerLoader;
import com.tencent.tinker.loader.TinkerRuntimeException;
import com.tencent.tinker.loader.TinkerUncaughtHandler;
import com.tencent.tinker.loader.shareutil.ShareConstants;
import com.tencent.tinker.loader.shareutil.ShareIntentUtil;
import com.tencent.tinker.loader.shareutil.ShareTinkerInternals;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

/**
 * Created by zhangshaowen on 16/3/8.
 */
public abstract class TinkerApplication extends Application {
    private static final String INTENT_PATCH_EXCEPTION = ShareIntentUtil.INTENT_PATCH_EXCEPTION;
    private static final String TINKER_LOADER_METHOD = "tryLoad";

    private static final TinkerApplication[] SELF_HOLDER = {null};


    // 合成哪些类型文件，dex/so lib/resource/all
    private final int tinkerFlags;
    // 是否在合成apk时校验md5
    private final boolean tinkerLoadVerifyFlag;
    // Application代理类(ApplicationLike)的包名
    private final String delegateClassName;
    // TinkerLoader类包名
    private final String loaderClassName;
    //
    private final boolean useDelegateLastClassLoader;

    /**
     * if we have load patch, we should use safe mode
     */
    private boolean useSafeMode;
    protected Intent tinkerResultIntent;

    protected ClassLoader mCurrentClassLoader = null;
    private Handler mInlineFence = null;

    protected TinkerApplication(int tinkerFlags) {
        this(tinkerFlags, "com.tencent.tinker.entry.DefaultApplicationLike",
                TinkerLoader.class.getName(), false, false);
    }

    protected TinkerApplication(int tinkerFlags, String delegateClassName) {
        this(tinkerFlags, delegateClassName, TinkerLoader.class.getName(), false, false);
    }

    protected TinkerApplication(int tinkerFlags, String delegateClassName,
                                String loaderClassName, boolean tinkerLoadVerifyFlag) {
        this(tinkerFlags, delegateClassName, loaderClassName, tinkerLoadVerifyFlag, true);
    }

    protected TinkerApplication(int tinkerFlags, String delegateClassName,
                                String loaderClassName, boolean tinkerLoadVerifyFlag,
                                boolean useDelegateLastClassLoader) {
        synchronized (SELF_HOLDER) {
            SELF_HOLDER[0] = this;
        }
        this.tinkerFlags = tinkerFlags;
        this.delegateClassName = delegateClassName;
        this.loaderClassName = loaderClassName;
        this.tinkerLoadVerifyFlag = tinkerLoadVerifyFlag;
        this.useDelegateLastClassLoader = useDelegateLastClassLoader;
    }

    public static TinkerApplication getInstance() {
        synchronized (SELF_HOLDER) {
            if (SELF_HOLDER[0] == null) {
                throw new IllegalStateException("TinkerApplication is not initialized.");
            }
            return SELF_HOLDER[0];
        }
    }

    private void loadTinker() {
        try {
            // 因为loader类可以被开发者自定义，所以反射创建tinker loader实例，默认为TinkerLoader类
            Class<?> tinkerLoadClass = Class.forName(loaderClassName, false, TinkerApplication.class.getClassLoader());
            // 调用TinkerLoader tryLoad
            Method loadMethod = tinkerLoadClass.getMethod(TINKER_LOADER_METHOD, TinkerApplication.class);
            Constructor<?> constructor = tinkerLoadClass.getConstructor();
            tinkerResultIntent = (Intent) loadMethod.invoke(constructor.newInstance(), this);
        } catch (Throwable e) {
            //has exception, put exception error code
            tinkerResultIntent = new Intent();
            ShareIntentUtil.setIntentReturnCode(tinkerResultIntent, ShareConstants.ERROR_LOAD_PATCH_UNKNOWN_EXCEPTION);
            tinkerResultIntent.putExtra(INTENT_PATCH_EXCEPTION, e);
        }
    }

    private Handler createInlineFence(Application app,
                                      int tinkerFlags,
                                      String delegateClassName,
                                      boolean tinkerLoadVerifyFlag,
                                      long applicationStartElapsedTime,
                                      long applicationStartMillisTime,
                                      Intent resultIntent) {
        try {
            // 使用替换后的classLoader反射ApplicationLike类
            final Class<?> delegateClass = Class.forName(delegateClassName, false, mCurrentClassLoader);
            final Constructor<?> constructor = delegateClass.getConstructor(Application.class, int.class, boolean.class,
                    long.class, long.class, Intent.class);
            // 创建ApplicationLike实例
            final Object appLike = constructor.newInstance(app, tinkerFlags, tinkerLoadVerifyFlag,
                    applicationStartElapsedTime, applicationStartMillisTime, resultIntent);
            // 反射创建TinkerApplicationInlineFence
            final Class<?> inlineFenceClass = Class.forName(
                    "com.tencent.tinker.entry.TinkerApplicationInlineFence", false, mCurrentClassLoader);
            final Class<?> appLikeClass = Class.forName(
                    "com.tencent.tinker.entry.ApplicationLike", false, mCurrentClassLoader);
            final Constructor<?> inlineFenceCtor = inlineFenceClass.getConstructor(appLikeClass);
            inlineFenceCtor.setAccessible(true);
            return (Handler) inlineFenceCtor.newInstance(appLike);
        } catch (Throwable thr) {
            throw new TinkerRuntimeException("createInlineFence failed", thr);
        }
    }

    protected void onBaseContextAttached(Context base, long applicationStartElapsedTime, long applicationStartMillisTime) {
        try {
            // 反射调用loader类的tryLoad方法
            // 因为开发者可以自定义拓展loader，所以根据ApplicationLike中配置的loader类名反射调用
            // 加载补丁
            loadTinker();
            // loadTinker已经将app PathClassLoader替换，这里是替换后的cl
            mInlineFence = createInlineFence(this, tinkerFlags, delegateClassName,
                    tinkerLoadVerifyFlag, applicationStartElapsedTime, applicationStartMillisTime,
                    tinkerResultIntent);
            // 回调ApplicationLike onBaseContextAttached
            TinkerInlineFenceAction.callOnBaseContextAttached(mInlineFence, base);
            //reset save mode
            if (useSafeMode) {
                ShareTinkerInternals.setSafeModeCount(this, 0);
            }
        } catch (TinkerRuntimeException e) {
            throw e;
        } catch (Throwable thr) {
            throw new TinkerRuntimeException(thr.getMessage(), thr);
        }
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        // 系统启动了多久
        final long applicationStartElapsedTime = SystemClock.elapsedRealtime();
        final long applicationStartMillisTime = System.currentTimeMillis();
        // 异常捕获
        Thread.setDefaultUncaughtExceptionHandler(new TinkerUncaughtHandler(this));
        onBaseContextAttached(base, applicationStartElapsedTime, applicationStartMillisTime);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (mInlineFence == null) {
            return;
        }
        TinkerInlineFenceAction.callOnCreate(mInlineFence);
    }

    @Override
    public void onTerminate() {
        super.onTerminate();
        if (mInlineFence == null) {
            return;
        }
        TinkerInlineFenceAction.callOnTerminate(mInlineFence);
    }

    @Override
    public void onLowMemory() {
        super.onLowMemory();
        if (mInlineFence == null) {
            return;
        }
        TinkerInlineFenceAction.callOnLowMemory(mInlineFence);
    }

    @TargetApi(14)
    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        if (mInlineFence == null) {
            return;
        }
        TinkerInlineFenceAction.callOnTrimMemory(mInlineFence, level);
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        if (mInlineFence == null) {
            return;
        }
        TinkerInlineFenceAction.callOnConfigurationChanged(mInlineFence, newConfig);
    }

    @Override
    public Resources getResources() {
        final Resources resources = super.getResources();
        if (mInlineFence == null) {
            return resources;
        }
        return TinkerInlineFenceAction.callGetResources(mInlineFence, resources);
    }

    @Override
    public ClassLoader getClassLoader() {
        final ClassLoader classLoader = super.getClassLoader();
        if (mInlineFence == null) {
            return classLoader;
        }
        return TinkerInlineFenceAction.callGetClassLoader(mInlineFence, classLoader);
    }

    @Override
    public AssetManager getAssets() {
        final AssetManager assets = super.getAssets();
        if (mInlineFence == null) {
            return assets;
        }
        return TinkerInlineFenceAction.callGetAssets(mInlineFence, assets);
    }

    @Override
    public Object getSystemService(String name) {
        final Object service = super.getSystemService(name);
        if (mInlineFence == null) {
            return service;
        }
        return TinkerInlineFenceAction.callGetSystemService(mInlineFence, name, service);
    }

    @Override
    public Context getBaseContext() {
        final Context base = super.getBaseContext();
        if (mInlineFence == null) {
            return base;
        }
        return TinkerInlineFenceAction.callGetBaseContext(mInlineFence, base);
    }

    @Keep
    public int mzNightModeUseOf() {
        if (mInlineFence == null) {
            // Return 1 for default according to MeiZu's announcement.
            return 1;
        }
        return TinkerInlineFenceAction.callMZNightModeUseOf(mInlineFence);
    }

    public void setUseSafeMode(boolean useSafeMode) {
        this.useSafeMode = useSafeMode;
    }

    public boolean isTinkerLoadVerifyFlag() {
        return tinkerLoadVerifyFlag;
    }

    public int getTinkerFlags() {
        return tinkerFlags;
    }

    public boolean isUseDelegateLastClassLoader() {
        return useDelegateLastClassLoader;
    }
}
