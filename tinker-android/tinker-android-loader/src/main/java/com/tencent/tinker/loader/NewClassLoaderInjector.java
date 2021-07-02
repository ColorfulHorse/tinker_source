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

package com.tencent.tinker.loader;

import android.app.Application;
import android.content.Context;
import android.content.res.Resources;
import android.os.Build;

import java.io.File;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;

import dalvik.system.DelegateLastClassLoader;

/**
 * Created by tangyinsheng on 2019-10-31.
 */
final class NewClassLoaderInjector {
    public static ClassLoader inject(Application app, ClassLoader oldClassLoader, File dexOptDir,
                                     boolean useDLC, List<File> patchedDexes) throws Throwable {
        final String[] patchedDexPaths = new String[patchedDexes.size()];
        for (int i = 0; i < patchedDexPaths.length; ++i) {
            patchedDexPaths[i] = patchedDexes.get(i).getAbsolutePath();
        }
        // 创建classLoader
        final ClassLoader newClassLoader = createNewClassLoader(oldClassLoader,
              dexOptDir, useDLC, patchedDexPaths);
        // 替换classLoader
        doInject(app, newClassLoader);
        return newClassLoader;
    }

    public static void triggerDex2Oat(Context context, File dexOptDir, boolean useDLC,
                                      String... dexPaths) throws Throwable {
        final ClassLoader triggerClassLoader = createNewClassLoader(context.getClassLoader(), dexOptDir, useDLC, dexPaths);
    }

    @SuppressWarnings("unchecked")
    private static ClassLoader createNewClassLoader(ClassLoader oldClassLoader,
                                                    File dexOptDir,
                                                    boolean useDLC,
                                                    String... patchDexPaths) throws Throwable {
        // 反射获取BaseDexClassLoader的DexPathList字段
        // old oldClassLoader是当前app的PathClassLoader
        final Field pathListField = findField(
                Class.forName("dalvik.system.BaseDexClassLoader", false, oldClassLoader),
                "pathList");
        final Object oldPathList = pathListField.get(oldClassLoader);

        final StringBuilder dexPathBuilder = new StringBuilder();
        final boolean hasPatchDexPaths = patchDexPaths != null && patchDexPaths.length > 0;
        if (hasPatchDexPaths) {
            for (int i = 0; i < patchDexPaths.length; ++i) {
                if (i > 0) {
                    dexPathBuilder.append(File.pathSeparator);
                }
                dexPathBuilder.append(patchDexPaths[i]);
            }
        }
        // 拼接需要dex2oat的dex文件路径
        final String combinedDexPath = dexPathBuilder.toString();

        // 反射DexPathList中nativeLibraryDirectories字段，so库路径
        final Field nativeLibraryDirectoriesField = findField(oldPathList.getClass(), "nativeLibraryDirectories");
        List<File> oldNativeLibraryDirectories = null;
        if (nativeLibraryDirectoriesField.getType().isArray()) {
            oldNativeLibraryDirectories = Arrays.asList((File[]) nativeLibraryDirectoriesField.get(oldPathList));
        } else {
            oldNativeLibraryDirectories = (List<File>) nativeLibraryDirectoriesField.get(oldPathList);
        }
        final StringBuilder libraryPathBuilder = new StringBuilder();
        boolean isFirstItem = true;
        for (File libDir : oldNativeLibraryDirectories) {
            if (libDir == null) {
                continue;
            }
            if (isFirstItem) {
                isFirstItem = false;
            } else {
                libraryPathBuilder.append(File.pathSeparator);
            }
            libraryPathBuilder.append(libDir.getAbsolutePath());
        }
        // 拼接so库路径
        final String combinedLibraryPath = libraryPathBuilder.toString();

        ClassLoader result = null;
        if (useDLC && Build.VERSION.SDK_INT >= 27) {
            // https://developer.android.google.cn/reference/dalvik/system/DelegateLastClassLoader
            // https://www.androidos.net.cn/android/10.0.0_r6/xref/libcore/dalvik/src/main/java/dalvik/system/DelegateLastClassLoader.java
            // DelegateLastClassLoader是android8.1后新增的，继承于PathClassLoader，实行最后查找策略
            // 从boot classpath中查找类
            // 从该classLoader的dexPath中查找类
            // 最后从该classLoader的双亲中查找类
            // 最后查找策略没有遵守双亲委托，最后才从parent classloader中查找类
            result = new DelegateLastClassLoader(combinedDexPath, combinedLibraryPath, ClassLoader.getSystemClassLoader());
            // 将之前的PathClassLoader设为创建的DelegateLastClassLoader的双亲
            final Field parentField = ClassLoader.class.getDeclaredField("parent");
            parentField.setAccessible(true);
            parentField.set(result, oldClassLoader);
        } else {
            // 做的事情和DelegateLastClassLoader差不多
            result = new TinkerClassLoader(combinedDexPath, dexOptDir, combinedLibraryPath, oldClassLoader);
        }
        // Android8.0之前版本替换原本的PathClassLoader中PathList中的classLoader为新创建的
        // Android 8.0之后不支持多个类加载器同时使用同一个DexFile对象来定义类，所以不能替换
        if (Build.VERSION.SDK_INT < 26) {
            findField(oldPathList.getClass(), "definingContext").set(oldPathList, result);
        }
        return result;
    }

    private static void doInject(Application app, ClassLoader classLoader) throws Throwable {
        Thread.currentThread().setContextClassLoader(classLoader);
        // ContextWrapper.mBase是该app的ContextImpl实例，LoadedApk.makeApplication中创建
        final Context baseContext = (Context) findField(app.getClass(), "mBase").get(app);
        try {
            // 替换ContextImpl中mClassLoader
            findField(baseContext.getClass(), "mClassLoader").set(baseContext, classLoader);
        } catch (Throwable ignored) {
            // 8.0前ContextImpl中没有mClassLoader
        }
        // app的ContextImpl中mPackageInfo是一个LoadedApk实例
        final Object basePackageInfo = findField(baseContext.getClass(), "mPackageInfo").get(baseContext);
        // 替换LoadedApk的ClassLoader
        findField(basePackageInfo.getClass(), "mClassLoader").set(basePackageInfo, classLoader);

        if (Build.VERSION.SDK_INT < 27) {
            final Resources res = app.getResources();
            try {
                // 替换Resources中ClassLoader
                findField(res.getClass(), "mClassLoader").set(res, classLoader);

                final Object drawableInflater = findField(res.getClass(), "mDrawableInflater").get(res);
                if (drawableInflater != null) {
                    // 替换DrawableInflater中ClassLoader
                    findField(drawableInflater.getClass(), "mClassLoader").set(drawableInflater, classLoader);
                }
            } catch (Throwable ignored) {
                // Ignored.
            }
        }
    }

    private static Field findField(Class<?> clazz, String name) throws Throwable {
        Class<?> currClazz = clazz;
        while (true) {
            try {
                final Field result = currClazz.getDeclaredField(name);
                result.setAccessible(true);
                return result;
            } catch (Throwable ignored) {
                if (currClazz == Object.class) {
                    throw new NoSuchFieldException("Cannot find field "
                            + name + " in class " + clazz.getName() + " and its super classes.");
                } else {
                    currClazz = currClazz.getSuperclass();
                }
            }
        }
    }

    private NewClassLoaderInjector() {
        throw new UnsupportedOperationException();
    }
}