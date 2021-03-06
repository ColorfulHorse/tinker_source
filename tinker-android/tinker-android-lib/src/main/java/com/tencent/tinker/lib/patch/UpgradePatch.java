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

package com.tencent.tinker.lib.patch;

import android.content.Context;
import android.os.Build;

import com.tencent.tinker.lib.service.PatchResult;
import com.tencent.tinker.lib.tinker.Tinker;
import com.tencent.tinker.loader.shareutil.ShareTinkerLog;
import com.tencent.tinker.lib.util.UpgradePatchRetry;
import com.tencent.tinker.loader.shareutil.ShareConstants;
import com.tencent.tinker.loader.shareutil.SharePatchFileUtil;
import com.tencent.tinker.loader.shareutil.SharePatchInfo;
import com.tencent.tinker.loader.shareutil.ShareSecurityCheck;
import com.tencent.tinker.loader.shareutil.ShareTinkerInternals;

import java.io.File;
import java.io.IOException;
import java.util.Map;


/**
 * generate new patch, you can implement your own patch processor class
 * Created by zhangshaowen on 16/3/14.
 */
public class UpgradePatch extends AbstractPatch {
    private static final String TAG = "Tinker.UpgradePatch";

    @Override
    public boolean tryPatch(Context context, String tempPatchPath, PatchResult patchResult) {
        Tinker manager = Tinker.with(context);
        final File patchFile = new File(tempPatchPath);
        if (!manager.isTinkerEnabled() || !ShareTinkerInternals.isTinkerEnableWithSharedPreferences(context)) {
            return false;
        }

        if (!SharePatchFileUtil.isLegalFile(patchFile)) {
            return false;
        }
        // ?????????????????????????????????meta??????
        ShareSecurityCheck signatureCheck = new ShareSecurityCheck(context);
        // ????????????????????????TinkerId????????????MD5???meta?????????????????????
        int returnCode = ShareTinkerInternals.checkTinkerPackage(context, manager.getTinkerFlags(), patchFile, signatureCheck);
        if (returnCode != ShareConstants.ERROR_PACKAGE_CHECK_OK) {
            manager.getPatchReporter().onPatchPackageCheckFail(patchFile, returnCode);
            return false;
        }

        String patchMd5 = SharePatchFileUtil.getMD5(patchFile);
        if (patchMd5 == null) {
            return false;
        }
        // ?????????md5???????????????
        patchResult.patchVersion = patchMd5;

        ShareTinkerLog.i(TAG, "UpgradePatch tryPatch:patchMd5:%s", patchMd5);

        // data/data/??????/tinker
        final String patchDirectory = manager.getPatchDirectory().getAbsolutePath();

        File patchInfoLockFile = SharePatchFileUtil.getPatchInfoLockFile(patchDirectory);
        // data/data/??????/tinker/patch.info
        File patchInfoFile = SharePatchFileUtil.getPatchInfoFile(patchDirectory);
        // ??????package_meta.txt??????
        final Map<String, String> pkgProps = signatureCheck.getPackagePropertiesIfPresent();
        if (pkgProps == null) {
            ShareTinkerLog.e(TAG, "UpgradePatch packageProperties is null, do we process a valid patch apk ?");
            return false;
        }

        final String isProtectedAppStr = pkgProps.get(ShareConstants.PKGMETA_KEY_IS_PROTECTED_APP);
        final boolean isProtectedApp = (isProtectedAppStr != null && !isProtectedAppStr.isEmpty() && !"0".equals(isProtectedAppStr));
        // ????????????????????????????????????
        SharePatchInfo oldInfo = SharePatchInfo.readAndCheckPropertyWithLock(patchInfoFile, patchInfoLockFile);

        SharePatchInfo newInfo;

        if (oldInfo != null) {
            // ?????????????????????
            if (oldInfo.oldVersion == null || oldInfo.newVersion == null || oldInfo.oatDir == null) {
                ShareTinkerLog.e(TAG, "UpgradePatch tryPatch:onPatchInfoCorrupted");
                manager.getPatchReporter().onPatchInfoCorrupted(patchFile, oldInfo.oldVersion, oldInfo.newVersion);
                return false;
            }

            if (!SharePatchFileUtil.checkIfMd5Valid(patchMd5)) {
                ShareTinkerLog.e(TAG, "UpgradePatch tryPatch:onPatchVersionCheckFail md5 %s is valid", patchMd5);
                manager.getPatchReporter().onPatchVersionCheckFail(patchFile, oldInfo, patchMd5);
                return false;
            }
            // ??????????????????????????????????????????(??????OTA?????????????????????)
            // ???TinkerLoader????????????????????????????????????oatDir????????????interpret
            final boolean usingInterpret = oldInfo.oatDir.equals(ShareConstants.INTERPRET_DEX_OPTIMIZE_PATH);
            // ???????????????????????????????????????????????????????????????????????????????????????
            if (!usingInterpret && !ShareTinkerInternals.isNullOrNil(oldInfo.newVersion) && oldInfo.newVersion.equals(patchMd5) && !oldInfo.isRemoveNewVersion) {
                ShareTinkerLog.e(TAG, "patch already applied, md5: %s", patchMd5);

                // ????????????????????????????????????????????????????????????1
                UpgradePatchRetry.getInstance(context).onPatchResetMaxCheck(patchMd5);

                return true;
            }
            // ?????????????????????????????????????????????oatDir??????changing?????????????????????????????????????????????????????????
            final String finalOatDir = usingInterpret ? ShareConstants.CHANING_DEX_OPTIMIZE_PATH : oldInfo.oatDir;
            newInfo = new SharePatchInfo(oldInfo.oldVersion, patchMd5, isProtectedApp, false, Build.FINGERPRINT, finalOatDir, false);
        } else {
            // ?????????????????????
            newInfo = new SharePatchInfo("", patchMd5, isProtectedApp, false, Build.FINGERPRINT, ShareConstants.DEFAULT_DEX_OPTIMIZE_PATH, false);
        }

        final String patchName = SharePatchFileUtil.getPatchVersionDirectory(patchMd5);
        // data/data/??????/tinker/patch-xxx
        final String patchVersionDirectory = patchDirectory + "/" + patchName;

        ShareTinkerLog.i(TAG, "UpgradePatch tryPatch:patchVersionDirectory:%s", patchVersionDirectory);

        // data/data/??????/tinker/patch-xxx/patch-xxx.apk
        File destPatchFile = new File(patchVersionDirectory + "/" + SharePatchFileUtil.getPatchVersionFile(patchMd5));

        try {
            if (!patchMd5.equals(SharePatchFileUtil.getMD5(destPatchFile))) {
                // ???????????????????????????destPatchFile??????
                SharePatchFileUtil.copyFileUsingStream(patchFile, destPatchFile);
                ShareTinkerLog.w(TAG, "UpgradePatch copy patch file, src file: %s size: %d, dest file: %s size:%d", patchFile.getAbsolutePath(), patchFile.length(),
                    destPatchFile.getAbsolutePath(), destPatchFile.length());
            }
        } catch (IOException e) {
            ShareTinkerLog.e(TAG, "UpgradePatch tryPatch:copy patch file fail from %s to %s", patchFile.getPath(), destPatchFile.getPath());
            manager.getPatchReporter().onPatchTypeExtractFail(patchFile, destPatchFile, patchFile.getName(), ShareConstants.TYPE_PATCH_FILE);
            return false;
        }

        // ??????dex?????????????????????dex2oat
        if (!DexDiffPatchInternal.tryRecoverDexFiles(manager, signatureCheck, context, patchVersionDirectory, destPatchFile, patchResult)) {
            ShareTinkerLog.e(TAG, "UpgradePatch tryPatch:new patch recover, try patch dex failed");
            return false;
        }
        // ???????????????????????????
        if (!ArkHotDiffPatchInternal.tryRecoverArkHotLibrary(manager, signatureCheck,
                context, patchVersionDirectory, destPatchFile)) {
            return false;
        }
        // BSDiff??????so???????????????????????????dex????????????????????????BSPatch.patchFast??????
        if (!BsDiffPatchInternal.tryRecoverLibraryFiles(manager, signatureCheck, context, patchVersionDirectory, destPatchFile)) {
            ShareTinkerLog.e(TAG, "UpgradePatch tryPatch:new patch recover, try patch library failed");
            return false;
        }
        // BSDiff??????????????????????????????????????????dex????????????????????????BSPatch.patchFast??????
        // ????????????data/data/??????/tinker/patch-xxx/res/resources.apk
        if (!ResDiffPatchInternal.tryRecoverResourceFiles(manager, signatureCheck, context, patchVersionDirectory, destPatchFile)) {
            ShareTinkerLog.e(TAG, "UpgradePatch tryPatch:new patch recover, try patch resource failed");
            return false;
        }

        // ??????dex2oat??????????????????????????????vivo/oppo???????????????dex2oat
        if (!DexDiffPatchInternal.waitAndCheckDexOptFile(patchFile, manager)) {
            ShareTinkerLog.e(TAG, "UpgradePatch tryPatch:new patch recover, check dex opt file failed");
            return false;
        }
        // ??????????????????????????????patch.info??????
        if (!SharePatchInfo.rewritePatchInfoFileWithLock(patchInfoFile, newInfo, patchInfoLockFile)) {
            ShareTinkerLog.e(TAG, "UpgradePatch tryPatch:new patch recover, rewrite patch info failed");
            manager.getPatchReporter().onPatchInfoCorrupted(patchFile, newInfo.oldVersion, newInfo.newVersion);
            return false;
        }

        // ?????????????????????????????????
        UpgradePatchRetry.getInstance(context).onPatchResetMaxCheck(patchMd5);
        return true;
    }
}
