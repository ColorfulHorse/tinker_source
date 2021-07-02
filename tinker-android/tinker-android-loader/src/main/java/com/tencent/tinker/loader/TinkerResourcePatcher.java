/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.tencent.tinker.loader;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.os.Build;
import android.util.ArrayMap;
import android.util.Log;

import com.tencent.tinker.loader.shareutil.ShareConstants;
import com.tencent.tinker.loader.shareutil.SharePatchFileUtil;
import com.tencent.tinker.loader.shareutil.ShareReflectUtil;
import com.tencent.tinker.loader.shareutil.ShareTinkerLog;

import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static android.os.Build.VERSION.SDK_INT;
import static android.os.Build.VERSION_CODES.KITKAT;
import static com.tencent.tinker.loader.shareutil.ShareReflectUtil.findConstructor;
import static com.tencent.tinker.loader.shareutil.ShareReflectUtil.findField;
import static com.tencent.tinker.loader.shareutil.ShareReflectUtil.findMethod;

/**
 * Created by zhangshaowen on 16/9/21.
 * Thanks for Android Fragmentation
 */
class TinkerResourcePatcher {
    private static final String TAG = "Tinker.ResourcePatcher";
    private static final String TEST_ASSETS_VALUE = "only_use_to_test_tinker_resource.txt";

    // ResourcesManager中保存的Resources弱引用集合
    private static Collection<WeakReference<Resources>> references = null;
    private static Object currentActivityThread = null;
    // 新资源包的AssetManager
    private static AssetManager newAssetManager = null;

    // AssetManager.addAssetPath
    private static Method addAssetPathMethod = null;
    // AssetManager.addAssetPathAsSharedLibrary >=android7.0需要调用
    private static Method addAssetPathAsSharedLibraryMethod = null;
    // AssetManager.mStringBlocks字段
    private static Field stringBlocksField = null;
    // AssetManager.ensureStringBlocks
    private static Method ensureStringBlocksMethod = null;

    // Resources.mAssets
    private static Field assetsFiled = null;
    // Resources.mResourcesImpl
    private static Field resourcesImplFiled = null;
    // LoadedApk.mResDir
    private static Field resDir = null;
    // ActivityThread.mPackages
    private static Field packagesFiled = null;
    // ActivityThread.mResourcePackages
    private static Field resourcePackagesFiled = null;
    // ApplicationInfo.publicSourceDir
    private static Field publicSourceDirField = null;

    @SuppressWarnings("unchecked")
    public static void isResourceCanPatch(Context context) throws Throwable {
        //   - Replace mResDir to point to the external resource file instead of the .apk. This is
        //     used as the asset path for new Resources objects.
        //   - Set Application#mLoadedApk to the found LoadedApk instance

        // Find the ActivityThread instance for the current thread
        Class<?> activityThread = Class.forName("android.app.ActivityThread");
        // ActivityThread实例
        currentActivityThread = ShareReflectUtil.getActivityThread(context, activityThread);

        // LoadedApk
        Class<?> loadedApkClass;
        try {
            loadedApkClass = Class.forName("android.app.LoadedApk");
        } catch (ClassNotFoundException e) {
            loadedApkClass = Class.forName("android.app.ActivityThread$PackageInfo");
        }
        // app资源路径field
        resDir = findField(loadedApkClass, "mResDir");
        packagesFiled = findField(activityThread, "mPackages");
        if (Build.VERSION.SDK_INT < 27) {
            resourcePackagesFiled = findField(activityThread, "mResourcePackages");
        }

        // 当前AssetManager实例
        final AssetManager assets = context.getAssets();
        addAssetPathMethod = findMethod(assets, "addAssetPath", String.class);
        // >=android7.0并且使用了共享资源库的情况下还需要调用addAssetPathAsSharedLibrary
        if (shouldAddSharedLibraryAssets(context.getApplicationInfo())) {
            addAssetPathAsSharedLibraryMethod =
                    findMethod(assets, "addAssetPathAsSharedLibrary", String.class);
        }

        // Kitkat needs this method call, Lollipop doesn't. However, it doesn't seem to cause any harm
        // in L, so we do it unconditionally.
        try {
            stringBlocksField = findField(assets, "mStringBlocks");
            ensureStringBlocksMethod = findMethod(assets, "ensureStringBlocks");
        } catch (Throwable ignored) {
            // Ignored.
        }

        // 反射创建新AssetManager
        newAssetManager = (AssetManager) findConstructor(assets).newInstance();

        // 反射获取ResourcesManager中Resources集合
        if (SDK_INT >= KITKAT) {
            //pre-N
            // Find the singleton instance of ResourcesManager
            // 获取ResourcesManager单例
            final Class<?> resourcesManagerClass = Class.forName("android.app.ResourcesManager");
            final Method mGetInstance = findMethod(resourcesManagerClass, "getInstance");
            final Object resourcesManager = mGetInstance.invoke(null);
            try {
                // 4.4 ~ 6.0 mActiveResources
                Field fMActiveResources = findField(resourcesManagerClass, "mActiveResources");
                final ArrayMap<?, WeakReference<Resources>> activeResources19 =
                        (ArrayMap<?, WeakReference<Resources>>) fMActiveResources.get(resourcesManager);
                references = activeResources19.values();
            } catch (NoSuchFieldException ignore) {
                // >=7.0  ArrayList<WeakReference<Resources>> mResourceReferences
                final Field mResourceReferences = findField(resourcesManagerClass, "mResourceReferences");
                references = (Collection<WeakReference<Resources>>) mResourceReferences.get(resourcesManager);
            }
        } else {
            // < 4.4 ActivityThread.mActiveResources
            final Field fMActiveResources = findField(activityThread, "mActiveResources");
            final HashMap<?, WeakReference<Resources>> activeResources7 =
                    (HashMap<?, WeakReference<Resources>>) fMActiveResources.get(currentActivityThread);
            references = activeResources7.values();
        }
        // check resource
        if (references == null) {
            throw new IllegalStateException("resource references is null");
        }

        final Resources resources = context.getResources();

        // fix jianGuo pro has private field 'mAssets' with Resource
        // try use mResourcesImpl first
        if (SDK_INT >= 24) {
            try {
                // N moved the mAssets inside an mResourcesImpl field
                resourcesImplFiled = findField(resources, "mResourcesImpl");
            } catch (Throwable ignore) {
                // for safety
                assetsFiled = findField(resources, "mAssets");
            }
        } else {
            assetsFiled = findField(resources, "mAssets");
        }

        try {
            // 资源路径
            publicSourceDirField = findField(ApplicationInfo.class, "publicSourceDir");
        } catch (NoSuchFieldException ignore) {
            // Ignored.
        }
    }

    /**
     * @param context
     * @param externalResourceFile
     * @throws Throwable
     */
    public static void monkeyPatchExistingResources(Context context, String externalResourceFile) throws Throwable {
        // data/data/包名/tinker/patch-xxx/res/resources.apk
        if (externalResourceFile == null) {
            return;
        }

        final ApplicationInfo appInfo = context.getApplicationInfo();

        final Field[] packagesFields;
        if (Build.VERSION.SDK_INT < 27) {
            packagesFields = new Field[]{packagesFiled, resourcePackagesFiled};
        } else {
            packagesFields = new Field[]{packagesFiled};
        }
        // 遍历activityThread中的LoadedApk
        for (Field field : packagesFields) {
            final Object value = field.get(currentActivityThread);

            for (Map.Entry<String, WeakReference<?>> entry
                    : ((Map<String, WeakReference<?>>) value).entrySet()) {
                final Object loadedApk = entry.getValue().get();
                if (loadedApk == null) {
                    continue;
                }
                final String resDirPath = (String) resDir.get(loadedApk);
                // 找到原app的LoadedApk实例，将它的mResDir设为新资源包路径
                if (appInfo.sourceDir.equals(resDirPath)) {
                    resDir.set(loadedApk, externalResourceFile);
                }
            }
        }

        // newAssetManager为新创建的AssetManager，调用AssetManager.addAssetPath设置它的路径为新资源包
        if (((Integer) addAssetPathMethod.invoke(newAssetManager, externalResourceFile)) == 0) {
            throw new IllegalStateException("Could not create new AssetManager");
        }

        // 7.0后系统还需调用AssetManager.addAssetPathAsSharedLibrary
        // ApplicationInfo.sharedLibraryFiles存储app用到的共享资源库
        // 共享资源库就是像so库一样，可以将资源包共享给其他应用使用
        // 如果app用到了共享资源库，那么可能会遇到修复热修后 SharedLibrary R 类中的资源 ID 与 AssetManager 中 Package ID 不一致导致的资源找不到问题
        if (shouldAddSharedLibraryAssets(appInfo)) {
            for (String sharedLibrary : appInfo.sharedLibraryFiles) {
                if (!sharedLibrary.endsWith(".apk")) {
                    continue;
                }
                if (((Integer) addAssetPathAsSharedLibraryMethod.invoke(newAssetManager, sharedLibrary)) == 0) {
                    throw new IllegalStateException("AssetManager add SharedLibrary Fail");
                }
                Log.i(TAG, "addAssetPathAsSharedLibrary " + sharedLibrary);
            }
        }

        // 重新创建字符串资源索引
        if (stringBlocksField != null && ensureStringBlocksMethod != null) {
            stringBlocksField.set(newAssetManager, null);
            ensureStringBlocksMethod.invoke(newAssetManager);
        }
        // 遍历ResourcesManager中Resources
        for (WeakReference<Resources> wr : references) {
            final Resources resources = wr.get();
            if (resources == null) {
                continue;
            }
            try {
                // 将Resources.mAssets设为新创建的AssetManager
                assetsFiled.set(resources, newAssetManager);
            } catch (Throwable ignore) {
                // android7.0以后该字段为Resources.mResourcesImpl.mAssets
                final Object resourceImpl = resourcesImplFiled.get(resources);
                final Field implAssets = findField(resourceImpl, "mAssets");
                implAssets.set(resourceImpl, newAssetManager);
            }
            // 清除Resources中typedArray缓存
            clearPreloadTypedArrayIssue(resources);
            // 内部调用AssetManager.setConfiguration，刷新资源配置
            resources.updateConfiguration(resources.getConfiguration(), resources.getDisplayMetrics());
        }

        // Handle issues caused by WebView on Android N.
        // Issue: On Android N, if an activity contains a webview, when screen rotates
        // our resource patch may lost effects.
        // for 5.x/6.x, we found Couldn't expand RemoteView for StatusBarNotification Exception
        // android7.0之后，如果activity包含webView，屏幕旋转后补丁资源会失效
        if (Build.VERSION.SDK_INT >= 24) {
            try {
                if (publicSourceDirField != null) {
                    // 重设ApplicationInfo.publicSourceDir
                    publicSourceDirField.set(context.getApplicationInfo(), externalResourceFile);
                }
            } catch (Throwable ignore) {
                // Ignored.
            }
        }
        // 以类似test.dex的方式检查补丁资源是否加载成功
        if (!checkResUpdate(context)) {
            throw new TinkerRuntimeException(ShareConstants.CHECK_RES_INSTALL_FAIL);
        }
    }

    /**
     * Why must I do these?
     * Resource has mTypedArrayPool field, which just like Message Poll to reduce gc
     * MiuiResource change TypedArray to MiuiTypedArray, but it get string block from offset instead of assetManager
     */
    private static void clearPreloadTypedArrayIssue(Resources resources) {
        // Perform this trick not only in Miui system since we can't predict if any other
        // manufacturer would do the same modification to Android.
        // if (!isMiuiSystem) {
        //     return;
        // }
        ShareTinkerLog.w(TAG, "try to clear typedArray cache!");
        // Clear typedArray cache.
        try {
            // Resources.mTypedArrayPool
            final Field typedArrayPoolField = findField(Resources.class, "mTypedArrayPool");
            final Object origTypedArrayPool = typedArrayPoolField.get(resources);
            // SynchronizedPool.acquire
            final Method acquireMethod = findMethod(origTypedArrayPool, "acquire");
            while (true) {
                if (acquireMethod.invoke(origTypedArrayPool) == null) {
                    break;
                }
            }
        } catch (Throwable ignored) {
            ShareTinkerLog.e(TAG, "clearPreloadTypedArrayIssue failed, ignore error: " + ignored);
        }
    }

    private static boolean checkResUpdate(Context context) {
        InputStream is = null;
        try {
            is = context.getAssets().open(TEST_ASSETS_VALUE);
        } catch (Throwable e) {
            ShareTinkerLog.e(TAG, "checkResUpdate failed, can't find test resource assets file " + TEST_ASSETS_VALUE + " e:" + e.getMessage());
            return false;
        } finally {
            SharePatchFileUtil.closeQuietly(is);
        }
        ShareTinkerLog.i(TAG, "checkResUpdate success, found test resource assets file " + TEST_ASSETS_VALUE);
        return true;
    }

    private static boolean shouldAddSharedLibraryAssets(ApplicationInfo applicationInfo) {
        return SDK_INT >= Build.VERSION_CODES.N && applicationInfo != null &&
                applicationInfo.sharedLibraryFiles != null;
    }
}
