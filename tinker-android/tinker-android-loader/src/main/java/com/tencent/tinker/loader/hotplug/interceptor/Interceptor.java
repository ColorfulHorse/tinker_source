package com.tencent.tinker.loader.hotplug.interceptor;

import android.util.Log;

import com.tencent.tinker.loader.shareutil.ShareTinkerLog;

/**
 * Created by tangyinsheng on 2017/7/31.
 */

public abstract class Interceptor<T_TARGET> {
    private static final String TAG = "Tinker.Interceptor";

    private T_TARGET mTarget = null;
    private volatile boolean mInstalled = false;

    protected abstract T_TARGET fetchTarget() throws Throwable;

    protected T_TARGET decorate(T_TARGET target) throws Throwable {
        return target;
    }

    protected abstract void inject(T_TARGET decorated) throws Throwable;

    public synchronized void install() throws InterceptFailedException {
        try {
            // fetchTarget获取要hook的实例，比如AMS客户端代理（IBinder对象）
            final T_TARGET target = fetchTarget();
            mTarget = target;
            // 创建将要hook对象的动态代理
            final T_TARGET decorated = decorate(target);
            if (decorated != target) {
                // 动态代理对象替换掉原对象完成hook
                inject(decorated);
            } else {
                ShareTinkerLog.w(TAG, "target: " + target + " was already hooked.");
            }
            mInstalled = true;
        } catch (Throwable thr) {
            mTarget = null;
            throw new InterceptFailedException(thr);
        }
    }

    public synchronized void uninstall() throws InterceptFailedException {
        if (mInstalled) {
            try {
                inject(mTarget);
                mTarget = null;
                mInstalled = false;
            } catch (Throwable thr) {
                throw new InterceptFailedException(thr);
            }
        }
    }

    protected interface ITinkerHotplugProxy {
        // Marker interface for proxy objects created by tinker.
    }
}
