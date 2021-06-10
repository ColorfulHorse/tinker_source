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
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles: tinker is disable, just return");
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_DISABLE);
            return;
        }
        // 是否在:patch进程，patch进程用来合成，并不用来加载
        if (ShareTinkerInternals.isInPatchProcess(app)) {
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles: we don't load patch with :patch process itself, just return");
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_DISABLE);
            return;
        }
        // 获取用于合成patch的目录
        File patchDirectoryFile = SharePatchFileUtil.getPatchDirectory(app);
        if (patchDirectoryFile == null) {
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:getPatchDirectory == null");
            //treat as not exist
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_DIRECTORY_NOT_EXIST);
            return;
        }
        String patchDirectoryPath = patchDirectoryFile.getAbsolutePath();
        if (!patchDirectoryFile.exists()) {
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:patch dir not exist:" + patchDirectoryPath);
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_DIRECTORY_NOT_EXIST);
            return;
        }

        // 获取patch.info文件
        File patchInfoFile = SharePatchFileUtil.getPatchInfoFile(patchDirectoryPath);

        //check patch info file whether exist
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

        String oldVersion = patchInfo.oldVersion;
        String newVersion = patchInfo.newVersion;
        String oatDex = patchInfo.oatDir;

        if (oldVersion == null || newVersion == null || oatDex == null) {
            //it is nice to clean patch
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:onPatchInfoCorrupted");
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_INFO_CORRUPTED);
            return;
        }
        // 是否主进程（app运行的进程）
        boolean mainProcess = ShareTinkerInternals.isInMainProcess(app);
        boolean isRemoveNewVersion = patchInfo.isRemoveNewVersion;

        if (mainProcess) {
            final String patchName = SharePatchFileUtil.getPatchVersionDirectory(newVersion);
            // So far new version is not loaded in main process and other processes.
            // We can remove new version directory safely.
            // 是否清除新补丁，如果补丁没有被加载，则可以直接删除
            if (isRemoveNewVersion) {
                ShareTinkerLog.w(TAG, "found clean patch mark and we are in main process, delete patch file now.");
                if (patchName != null) {
                    // 新旧版本号相同说明补丁已经被加载过
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
                    // 删除补丁
                    String patchVersionDirFullPath = patchDirectoryPath + "/" + patchName;
                    SharePatchFileUtil.deleteDir(patchVersionDirFullPath);

                    if (isNewVersionLoadedBefore) {
                        // 如果已经加载了补丁，则杀死patch(合成补丁)进程
                        ShareTinkerInternals.killProcessExceptMain(app);
                        ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_DIRECTORY_NOT_EXIST);
                        return;
                    }
                }
            }
            // OTA
            // 是否删除解释编译产生的odex文件
            if (patchInfo.isRemoveInterpretOATDir) {
                // delete interpret odex
                // for android o, directory change. Fortunately, we don't need to support android o interpret mode any more
                ShareTinkerLog.i(TAG, "tryLoadPatchFiles: isRemoveInterpretOATDir is true, try to delete interpret optimize files");
                // 重写patch.info删除odex标识，然后杀死patch进程并且删除odex文件
                patchInfo.isRemoveInterpretOATDir = false;
                SharePatchInfo.rewritePatchInfoFileWithLock(patchInfoFile, patchInfo, patchInfoLockFile);
                ShareTinkerInternals.killProcessExceptMain(app);
                String patchVersionDirFullPath = patchDirectoryPath + "/" + patchName;
                SharePatchFileUtil.deleteDir(patchVersionDirFullPath + "/" + ShareConstants.INTERPRET_DEX_OPTIMIZE_PATH);
            }
        }

        resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_OLD_VERSION, oldVersion);
        resultIntent.putExtra(ShareIntentUtil.INTENT_PATCH_NEW_VERSION, newVersion);

        boolean versionChanged = !(oldVersion.equals(newVersion));
        // 编译模式是否改变了 解释模式/aot模式
        boolean oatModeChanged = oatDex.equals(ShareConstants.CHANING_DEX_OPTIMIZE_PATH);
        // 编译模式 odex/interpet，解释模式在系统OTA后在子进程进行
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
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:patchName is null");
            //we may delete patch info file
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_VERSION_DIRECTORY_NOT_EXIST);
            return;
        }
        // 待加载的补丁路径 tinker/patch.info/patch-641e634c
        String patchVersionDirectory = patchDirectoryPath + "/" + patchName;

        File patchVersionDirectoryFile = new File(patchVersionDirectory);

        if (!patchVersionDirectoryFile.exists()) {
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:onPatchVersionDirectoryNotFound");
            //we may delete patch info file
            ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_VERSION_DIRECTORY_NOT_EXIST);
            return;
        }

        // 补丁文件：tinker/patch.info/patch-641e634c/patch-641e634c.apk
        final String patchVersionFileRelPath = SharePatchFileUtil.getPatchVersionFile(version);
        File patchVersionFile = (patchVersionFileRelPath != null ? new File(patchVersionDirectoryFile.getAbsolutePath(), patchVersionFileRelPath) : null);
        // 非法文件则停止加载并删除
        if (!SharePatchFileUtil.isLegalFile(patchVersionFile)) {
            ShareTinkerLog.w(TAG, "tryLoadPatchFiles:onPatchVersionFileNotFound");
            //we may delete patch info file
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
        // 是否运了方舟编译器
        final boolean isArkHotRuning = ShareTinkerInternals.isArkHotRuning();

        if (!isArkHotRuning && isEnabledForDex) {
            //tinker/patch.info/patch-641e634c/dex
            // 校验补丁包中的dex文件，解析dex_meta文件中的内容
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
                //file not found, do not load patch
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
                // 主进程直接删除
                // Mark current patch as deleted so that other process will not load patch after reboot.
                patchInfo.oldVersion = "";
                patchInfo.newVersion = "";
                patchInfo.isRemoveNewVersion = false;
                SharePatchInfo.rewritePatchInfoFileWithLock(patchInfoFile, patchInfo, patchInfoLockFile);
                ShareTinkerInternals.killProcessExceptMain(app);

                // Actually delete patch files.
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

        //
        if (!isArkHotRuning && isEnabledForDex) {
            //
            boolean loadTinkerJars = TinkerDexLoader.loadTinkerJars(app, patchVersionDirectory, oatDex, resultIntent, isSystemOTA, isProtectedApp);

            if (isSystemOTA) {
                // update fingerprint after load success
                patchInfo.fingerPrint = Build.FINGERPRINT;
                patchInfo.oatDir = loadTinkerJars ? ShareConstants.INTERPRET_DEX_OPTIMIZE_PATH : ShareConstants.DEFAULT_DEX_OPTIMIZE_PATH;
                // reset to false
                oatModeChanged = false;

                if (!SharePatchInfo.rewritePatchInfoFileWithLock(patchInfoFile, patchInfo, patchInfoLockFile)) {
                    ShareIntentUtil.setIntentReturnCode(resultIntent, ShareConstants.ERROR_LOAD_PATCH_REWRITE_PATCH_INFO_FAIL);
                    ShareTinkerLog.w(TAG, "tryLoadPatchFiles:onReWritePatchInfoCorrupted");
                    return;
                }
                // update oat dir
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

        //now we can load patch resource
        if (isEnabledForResource) {
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
