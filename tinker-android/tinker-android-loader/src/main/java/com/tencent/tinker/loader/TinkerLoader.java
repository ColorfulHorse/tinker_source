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

import android.content.Intent;
import android.os.Build;
import android.os.SystemClock;
import android.view.View;

import com.tencent.tinker.loader.app.TinkerApplication;
import com.tencent.tinker.loader.hotplug.ComponentHotplug;
import com.tencent.tinker.loader.shareutil.ShareConstants;
import com.tencent.tinker.loader.shareutil.ShareIntentUtil;
import com.tencent.tinker.loader.shareutil.SharePatchFileUtil;
import com.tencent.tinker.loader.shareutil.SharePatchInfo;
import com.tencent.tinker.loader.shareutil.ShareSecurityCheck;
import com.tencent.tinker.loader.shareutil.ShareTinkerInternals;
import com.tencent.tinker.loader.shareutil.ShareTinkerLog;

import java.io.File;

/**
 * Created by zhangshaowen on 16/3/10.
 * Warning, it is special for loader classes, they can't change through tinker patch.
 * thus, it's reference class must put in the tinkerPatch.dex.loader{} and the android main dex pattern through gradle
 */
public class TinkerLoader extends AbstractTinkerLoader {
    private static final String TAG = "Tinker.TinkerLoader";

    /**
     * the patch info file
     */
    private SharePatchInfo patchInfo;

    /**
     * only main process can handle patch version change or incomplete
     */
    @Override
    public Intent tryLoad(TinkerApplication app) {
        ShareTinkerLog.d(TAG, "tryLoad test test");
        // intent记录加载补丁的信息
        Intent resultIntent = new Intent();
        long begin = SystemClock.elapsedRealtime();
        tryLoadPatchFilesInternal(app, resultIntent);
        long cost = SystemClock.elapsedRealtime() - begin;
        ShareIntentUtil.setIntentPatchCostTime(resultIntent, cost);
        return resultIntent;
    }

    private void tryLoadPatchFilesInternal(TinkerApplication app, Intent resultIntent) {
        final int tinkerFlag = app.getTinkerFlags();
        // 是否启用
        if (!ShareTinkerInternals.isTinkerEnabled(tinkerFlag)) {
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_DISABLE);
            return;
        }
        // 是否在:patch进程，patch进程用来合成，并不用来加载
        if (ShareTinkerInternals.isInPatchProcess(app)) {
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_DISABLE);
            return;
        }
        // 校验补丁目录以及文件是否存在
        File patchDirectoryFile = SharePatchFileUtil.getPatchDirectory(app);
        if (patchDirectoryFile == null) {
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_DIRECTORY_NOT_EXIST);
            return;
        }
        String patchDirectoryPath = patchDirectoryFile.getAbsolutePath();
        if (!patchDirectoryFile.exists()) {
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_DIRECTORY_NOT_EXIST);
            return;
        }

        // patch.info文件是否存在
        File patchInfoFile = SharePatchFileUtil.getPatchInfoFile(patchDirectoryPath);
        if (!patchInfoFile.exists()) {
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:patch info not exist:" + patchInfoFile.getAbsolutePath());
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_INFO_NOT_EXIST);
            return;
        }
        // 获取info.lock文件
        File patchInfoLockFile = SharePatchFileUtil.getPatchInfoLockFile(patchDirectoryPath);
        // 读取patch.info文件中记录的信息
        patchInfo = SharePatchInfo.readAndCheckPropertyWithLock(patchInfoFile, patchInfoLockFile);
        if (patchInfo == null) {
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_INFO_CORRUPTED);
            return;
        }

        final boolean isProtectedApp = patchInfo.isProtectedApp;
        resultIntent.putExtra(ShareIntentUtil.INTENT_IS_PROTECTED_APP, isProtectedApp);
        // 上一次加载的补丁版本
        String oldVersion = patchInfo.oldVersion;
        // 当前需要加载的补丁版本
        String newVersion = patchInfo.newVersion;
        String oatDex = patchInfo.oatDir;
        if (oldVersion == null || newVersion == null || oatDex == null) {
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_INFO_CORRUPTED);
            return;
        }
        // 是否主进程（app运行的进程）
        boolean mainProcess = ShareTinkerInternals.isInMainProcess(app);
        boolean isRemoveNewVersion = patchInfo.isRemoveNewVersion;

        if (mainProcess) {
            final String patchName = SharePatchFileUtil.getPatchVersionDirectory(newVersion);
            // 是否清除所有补丁，若补丁被加载过需要重置patch.info并杀死主进程以外所有进程
            if (isRemoveNewVersion) {
                if (patchName != null) {
                    // 新旧版本号相同说明该补丁之前被加载过
                    final boolean isNewVersionLoadedBefore = oldVersion.equals(newVersion);
                    // 重置补丁信息
                    if (isNewVersionLoadedBefore) {
                        oldVersion = "";
                    }
                    newVersion = oldVersion;
                    patchInfo.oldVersion = oldVersion;
                    patchInfo.newVersion = newVersion;
                    patchInfo.isRemoveNewVersion = false;
                    SharePatchInfo.rewritePatchInfoFileWithLock(patchInfoFile, patchInfo, patchInfoLockFile);
                    // 删除补丁文件
                    String patchVersionDirFullPath = patchDirectoryPath + "/" + patchName;
                    SharePatchFileUtil.deleteDir(patchVersionDirFullPath);

                    if (isNewVersionLoadedBefore) {
                        // 如果已经加载过补丁，则杀死其他进程
                        ShareTinkerInternals.killProcessExceptMain(app);
                        ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_DIRECTORY_NOT_EXIST);
                        return;
                    }
                }
            }
            // 是否删除解释编译产生的odex文件
            if (patchInfo.isRemoveInterpretOATDir) {
                // 重写patch.info删除odex标识，然后杀死其他进程并且删除odex文件
                patchInfo.isRemoveInterpretOATDir = false;
                SharePatchInfo.rewritePatchInfoFileWithLock(patchInfoFile, patchInfo, patchInfoLockFile);
                ShareTinkerInternals.killProcessExceptMain(app);
                String patchVersionDirFullPath = patchDirectoryPath + "/" + patchName;
                // data/data/包名/tinker/patch-xxx/interpet
                SharePatchFileUtil.deleteDir(patchVersionDirFullPath + "/" + ShareConstants.INTERPRET_DEX_OPTIMIZE_PATH);
            }
        }

        resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_OLD_VERSION, oldVersion);
        resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_NEW_VERSION, newVersion);
        // oldVersion和newVersion不同说明合成了新补丁，但是还没有加载过
        boolean versionChanged = !(oldVersion.equals(newVersion));
        // changing代表后台dex2oat已经完成，切换到非解释模式
        // 此时使用dex2oat生成的odex文件，删除解释模式的odex文件
        boolean oatModeChanged = oatDex.equals(ShareConstants.CHANING_DEX_OPTIMIZE_PATH);
        oatDex = ShareTinkerInternals.getCurrentOatMode(app, oatDex);
        resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_OAT_DIR, oatDex);

        String version = oldVersion;
        if (versionChanged && mainProcess) {
            version = newVersion;
        }
        if (ShareTinkerInternals.isNullOrNil(version)) {
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:version is blank, wait main process to restart");
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_INFO_BLANK);
            return;
        }

        // 待加载的补丁名：patch-641e634c
        String patchName = SharePatchFileUtil.getPatchVersionDirectory(version);
        if (patchName == null) {
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_VERSION_DIRECTORY_NOT_EXIST);
            return;
        }
        // 待加载的补丁路径 data/data/包名/tinker/patch-641e634c
        String patchVersionDirectory = patchDirectoryPath + "/" + patchName;

        File patchVersionDirectoryFile = new File(patchVersionDirectory);

        if (!patchVersionDirectoryFile.exists()) {
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_VERSION_DIRECTORY_NOT_EXIST);
            return;
        }

        final String patchVersionFileRelPath = SharePatchFileUtil.getPatchVersionFile(version);
        // 补丁文件：data/data/包名/tinker/patch-md5/patch-md5.apk
        File patchVersionFile = (patchVersionFileRelPath != null ? new File(patchVersionDirectoryFile.getAbsolutePath(), patchVersionFileRelPath) : null);
        // 非法文件则停止加载并删除
        if (!SharePatchFileUtil.isLegalFile(patchVersionFile)) {
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_VERSION_FILE_NOT_EXIST);
            return;
        }

        // 此类用于读取补丁包中的meta文件进行校验
        ShareSecurityCheck securityCheck = new ShareSecurityCheck(app);
        // 校验补丁的TinkerId、签名、MD5、meta文件等的合法性
        int returnCode = ShareTinkerInternals.checkTinkerPackage(app, tinkerFlag, patchVersionFile, securityCheck);
        if (returnCode != ShareConstants.ERROR_PACKAGE_CHECK_OK) {
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:checkTinkerPackage");
            resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_PACKAGE_PATCH_CHECK, returnCode);
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_PACKAGE_CHECK_FAIL);
            return;
        }
        resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_PACKAGE_CONFIG, securityCheck.getPackagePropertiesIfPresent());

        // 是否合成dex
        final boolean isEnabledForDex = ShareTinkerInternals.isTinkerEnabledForDex(tinkerFlag);
        // 是否方舟编译器
        final boolean isArkHotRuning = ShareTinkerInternals.isArkHotRuning();

        if (!isArkHotRuning && isEnabledForDex) {
            // .../patch-641e634c/dex
            // 解析dex_meta，校验要加载的dex以及对应的的odex是否存在
            boolean dexCheck = TinkerDexLoader.checkComplete(patchVersionDirectory, securityCheck, oatDex, resultIntent);
            if (!dexCheck) {
                //file not found, do not load patch
                ShareTinkerLog.w(TAG, "tryLoadPatchFiles:dex check fail");
                return;
            }
        }

        final boolean isEnabledForArkHot = ShareTinkerInternals.isTinkerEnabledForArkHot(tinkerFlag);
        if (isArkHotRuning && isEnabledForArkHot) {
            // 校验方舟编译器patch.apk
            boolean arkHotCheck = TinkerArkHotLoader.checkComplete(patchVersionDirectory, securityCheck, resultIntent);
            if (!arkHotCheck) {
                // file not found, do not load patch
                ShareTinkerLog.w(TAG, "tryLoadPatchFiles:dex check fail");
                return;
            }
        }


        final boolean isEnabledForNativeLib = ShareTinkerInternals.isTinkerEnabledForNativeLib(tinkerFlag);

        if (isEnabledForNativeLib) {
            // 校验so库合法性
            boolean libCheck = TinkerSoLoader.checkComplete(patchVersionDirectory, securityCheck, resultIntent);
            if (!libCheck) {
                ShareTinkerLog.w(TAG, "tryLoadPatchFiles:native lib check fail");
                return;
            }
        }

        final boolean isEnabledForResource = ShareTinkerInternals.isTinkerEnabledForResource(tinkerFlag);
        ShareTinkerLog.w(TAG, "tryLoadPatchFiles:isEnabledForResource:" + isEnabledForResource);
        if (isEnabledForResource) {
            // 校验补丁资源正确性
            boolean resourceCheck = TinkerResourceLoader.checkComplete(app, patchVersionDirectory, securityCheck, resultIntent);
            if (!resourceCheck) {
                ShareTinkerLog.w(TAG, "try LoadPatchFiles:resource check fail");
                return;
            }
        }
        //only work for art platform oat，because of interpret, refuse 4.4 art oat
        //android o use quicken default, we don't need to use interpret mode
        // 判断系统是否进行了OTA升级，系统OTA后首次启动需要先以解释模式运行
        boolean isSystemOTA = ShareTinkerInternals.isVmArt()
            && ShareTinkerInternals.isSystemOTA(patchInfo.fingerPrint)
            && Build.VERSION.SDK_INT >= 21 && !ShareTinkerInternals.isAfterAndroidO();

        resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_SYSTEM_OTA, isSystemOTA);

        //we should first try rewrite patch info file, if there is a error, we can't load jar
        if (mainProcess) {
            if (versionChanged) {
                patchInfo.oldVersion = version;
            }

            if (oatModeChanged) {
                patchInfo.oatDir = oatDex;
                patchInfo.isRemoveInterpretOATDir = true;
            }
        }

        // 判断是否安全模式，也就是加载补丁是否失败了超过三次，超过三次之后直接删除对应补丁回退
        if (!checkSafeModeCount(app)) {
            if (mainProcess) {
                // 主进程杀死其他进程，然后直接删除
                patchInfo.oldVersion = "";
                patchInfo.newVersion = "";
                patchInfo.isRemoveNewVersion = false;
                SharePatchInfo.rewritePatchInfoFileWithLock(patchInfoFile, patchInfo, patchInfoLockFile);
                ShareTinkerInternals.killProcessExceptMain(app);

                String patchVersionDirFullPath = patchDirectoryPath + "/" + patchName;
                SharePatchFileUtil.deleteDir(patchVersionDirFullPath);

                resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_EXCEPTION, new TinkerRuntimeException("checkSafeModeCount fail"));
                ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_UNCAUGHT_EXCEPTION);
                ShareTinkerLog.w(TAG, "tryLoadPatchFiles:checkSafeModeCount fail, patch was deleted.");
                return;
            } else {
                // 非主进程将 patchInfo isRemoveNewVersion设为true，下次在主进程删除
                ShareTinkerLog.w(TAG, "tryLoadPatchFiles:checkSafeModeCount fail, but we are not in main process, mark the patch to be deleted and continue load patch.");
                ShareTinkerInternals.cleanPatch(app);
            }
        }

        if (!isArkHotRuning && isEnabledForDex) {
            // 加载dex，isSystemOTA = true以解释模式加载
            boolean loadTinkerJars = TinkerDexLoader.loadTinkerJars(app, patchVersionDirectory, oatDex, resultIntent, isSystemOTA, isProtectedApp);

            if (isSystemOTA) {
                // update fingerprint after load success
                patchInfo.fingerPrint = Build.FINGERPRINT;
                // ota后第一次启动加载补丁成功，oatDir = interpet
                patchInfo.oatDir = loadTinkerJars ? ShareConstants.INTERPRET_DEX_OPTIMIZE_PATH : ShareConstants.DEFAULT_DEX_OPTIMIZE_PATH;
                // reset to false
                oatModeChanged = false;

                if (!SharePatchInfo.rewritePatchInfoFileWithLock(patchInfoFile, patchInfo, patchInfoLockFile)) {
                    ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_REWRITE_PATCH_INFO_FAIL);
                    ShareTinkerLog.w(TAG, "tryLoadPatchFiles:onReWritePatchInfoCorrupted");
                    return;
                }
                // intent中设置oatDir为interpret
                resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_OAT_DIR, patchInfo.oatDir);
            }
            if (!loadTinkerJars) {
                ShareTinkerLog.w(TAG, "tryLoadPatchFiles:onPatchLoadDexesFail");
                return;
            }
        }

        if (isArkHotRuning && isEnabledForArkHot) {
            boolean loadArkHotFixJars = TinkerArkHotLoader.loadTinkerArkHot(app, patchVersionDirectory, resultIntent);
            if (!loadArkHotFixJars) {
                ShareTinkerLog.w(TAG, "tryLoadPatchFiles:onPatchLoadArkApkFail");
                return;
            }
        }

        if (isEnabledForResource) {
            // 加载资源文件
            boolean loadTinkerResources = TinkerResourceLoader.loadTinkerResources(app, patchVersionDirectory, resultIntent);
            if (!loadTinkerResources) {
                ShareTinkerLog.w(TAG, "tryLoadPatchFiles:onPatchLoadResourcesFail");
                return;
            }
        }

        // Init component hotplug support.
        if ((isEnabledForDex || isEnabledForArkHot) && isEnabledForResource) {
            ComponentHotplug.install(app, securityCheck);
        }

        if (!AppInfoChangedBlocker.tryStart(app)) {
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:AppInfoChangedBlocker install fail.");
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_BAIL_HACK_FAILURE);
            return;
        }

        // Before successfully exit, we should update stored version info and kill other process
        // to make them load latest patch when we first applied newer one.
        if (mainProcess && (versionChanged || oatModeChanged)) {
            //update old version to new
            if (!SharePatchInfo.rewritePatchInfoFileWithLock(patchInfoFile, patchInfo, patchInfoLockFile)) {
                ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_REWRITE_PATCH_INFO_FAIL);
                ShareTinkerLog.w(TAG, "tryLoadPatchFiles:onReWritePatchInfoCorrupted");
                return;
            }

            ShareTinkerInternals.killProcessExceptMain(app);
        }

        //all is ok!
        ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_OK);
        ShareTinkerLog.i(TAG, "tryLoadPatchFiles: load end, ok!");
    }

    private boolean checkSafeModeCount(TinkerApplication application) {
        int count = ShareTinkerInternals.getSafeModeCount(application);
        if (count >= ShareConstants.TINKER_SAFE_MODE_MAX_COUNT - 1) {
            ShareTinkerInternals.setSafeModeCount(application, 0);
            return false;
        }
        application.setUseSafeMode(true);
        ShareTinkerInternals.setSafeModeCount(application, count + 1);
        return true;
    }
}
