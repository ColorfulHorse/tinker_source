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

package com.tencent.tinker.lib.listener;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.text.TextUtils;

import com.tencent.tinker.lib.service.TinkerPatchForeService;
import com.tencent.tinker.lib.service.TinkerPatchService;
import com.tencent.tinker.lib.tinker.Tinker;
import com.tencent.tinker.lib.tinker.TinkerLoadResult;
import com.tencent.tinker.lib.util.TinkerServiceInternals;
import com.tencent.tinker.lib.util.UpgradePatchRetry;
import com.tencent.tinker.loader.shareutil.ShareConstants;
import com.tencent.tinker.loader.shareutil.SharePatchFileUtil;
import com.tencent.tinker.loader.shareutil.SharePatchInfo;
import com.tencent.tinker.loader.shareutil.ShareTinkerInternals;

import java.io.File;

import static android.content.Context.BIND_AUTO_CREATE;

/**
 * Created by zhangshaowen on 16/3/14.
 */
public class DefaultPatchListener implements PatchListener {
    protected final Context context;
    private ServiceConnection connection;

    public DefaultPatchListener(Context context) {
        this.context = context;
    }

    /**
     * when we receive a patch, what would we do?
     * you can overwrite it
     *
     * @param path
     * @return
     */
    @Override
    public int onPatchReceived(String path) {
        final File patchFile = new File(path);
        // 差异apk md5
        final String patchMD5 = SharePatchFileUtil.getMD5(patchFile);
        // 校验补丁
        // Tag1============================
        // 检查是否应该合成该补丁
        // 补丁不合法/正在合成补丁/系统OTA后第一次启动/该版本补丁已经被加载/该版本补丁已经合成还未加载/该补丁合并失败超过阈值
        final int returnCode = patchCheck(path, patchMD5);
        if (returnCode == ShareConstants.ERROR_PATCH_OK) {
            // 绑定TinkerPatchForeService，它运行在:patch进程
            runForgService();
            // 启动TinkerPatchService合成补丁
            TinkerPatchService.runPatchService(context, path);
        } else {
            Tinker.with(context).getLoadReporter().onLoadPatchListenerReceiveFail(new File(path), returnCode);
        }
        return returnCode;
    }


    private void runForgService() {
        try {
            connection = new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    if (context != null && connection != null) {
                        try {
                            //Tinker在完成补丁后会尝试kill掉patch进程，如果不unbind会导致patch进程重启
                            context.unbindService(connection);
                        } catch (Throwable ignored) {
                            // Ignored.
                        }
                    }
                }

                @Override
                public void onBindingDied(ComponentName name) {
                }
            };
            Intent innerForgIntent = new Intent(context, TinkerPatchForeService.class);
            context.bindService(innerForgIntent, connection, BIND_AUTO_CREATE);
        } catch (Throwable ex) {
            //ignore forground service start error
        }
    }

    /**
     * 检查是否应该合成该补丁
     * 补丁不合法/正在合成补丁/系统OTA后第一次启动/该版本补丁已经被加载/该版本补丁已经合成还未加载/该补丁合并失败超过阈值
     */
    protected int patchCheck(String path, String patchMd5) {
        final Tinker manager = Tinker.with(context);
        // 是否启用了tinker
        if (!manager.isTinkerEnabled() || !ShareTinkerInternals.isTinkerEnableWithSharedPreferences(context)) {
            return ShareConstants.ERROR_PATCH_DISABLE;
        }
        // md5以及文件合法性校验
        if (TextUtils.isEmpty(patchMd5)) {
            return ShareConstants.ERROR_PATCH_NOTEXIST;
        }
        final File file = new File(path);
        if (!SharePatchFileUtil.isLegalFile(file)) {
            return ShareConstants.ERROR_PATCH_NOTEXIST;
        }

        // 不能在patch进程调用
        if (manager.isPatchProcess()) {
            return ShareConstants.ERROR_PATCH_INSERVICE;
        }

        // patch进程已经在运行则忽略
        if (TinkerServiceInternals.isTinkerPatchServiceRunning(context)) {
            return ShareConstants.ERROR_PATCH_RUNNING;
        }

        // 这里判断是否在7.0以下系统错误地开启了jit选项（7.0以上Art才重新引入jit，某些自定义rom会错误打开此选项）
        if (ShareTinkerInternals.isVmJit()) {
            return ShareConstants.ERROR_PATCH_JIT;
        }
        // 此次加载补丁的信息
        final TinkerLoadResult loadResult = manager.getTinkerLoadResultIfPresent();
        // 当前是否在以解释模式运行，true则说明需要重新做dexopt
        final boolean repairOptNeeded = manager.isMainProcess()
                && loadResult != null && loadResult.useInterpretMode;

        if (!repairOptNeeded) {
            if (manager.isTinkerLoaded() && loadResult != null) {
                String currentVersion = loadResult.currentVersion;
                // 该版本的补丁已经被加载则忽略
                if (patchMd5.equals(currentVersion)) {
                    return ShareConstants.ERROR_PATCH_ALREADY_APPLY;
                }
            }

            // Hit if we have already applied patch but main process did not restart.
            // 该补丁已经合成，但是主进程没有重启加载，这里也忽略，不再重复合成
            final String patchDirectory = manager.getPatchDirectory().getAbsolutePath();
            File patchInfoLockFile = SharePatchFileUtil.getPatchInfoLockFile(patchDirectory);
            File patchInfoFile = SharePatchFileUtil.getPatchInfoFile(patchDirectory);
            try {
                final SharePatchInfo currInfo = SharePatchInfo.readAndCheckPropertyWithLock(patchInfoFile, patchInfoLockFile);
                if (currInfo != null && !ShareTinkerInternals.isNullOrNil(currInfo.newVersion) && !currInfo.isRemoveNewVersion) {
                    if (patchMd5.equals(currInfo.newVersion)) {
                        return ShareConstants.ERROR_PATCH_ALREADY_APPLY;
                    }
                }
            } catch (Throwable ignored) {
                // Ignored.
            }
        }

        // 合成补丁重试次数超过阈值（20次）忽略
        if (!UpgradePatchRetry.getInstance(context).onPatchListenerCheck(patchMd5)) {
            return ShareConstants.ERROR_PATCH_RETRY_COUNT_LIMIT;
        }

        return ShareConstants.ERROR_PATCH_OK;
    }

}
