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
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.SystemClock;

import com.tencent.tinker.commons.dexpatcher.DexPatchApplier;
import com.tencent.tinker.commons.util.DigestUtil;
import com.tencent.tinker.commons.util.IOHelper;
import com.tencent.tinker.lib.service.PatchResult;
import com.tencent.tinker.lib.tinker.Tinker;
import com.tencent.tinker.loader.TinkerDexOptimizer;
import com.tencent.tinker.loader.TinkerRuntimeException;
import com.tencent.tinker.loader.app.TinkerApplication;
import com.tencent.tinker.loader.shareutil.ShareConstants;
import com.tencent.tinker.loader.shareutil.ShareDexDiffPatchInfo;
import com.tencent.tinker.loader.shareutil.ShareElfFile;
import com.tencent.tinker.loader.shareutil.SharePatchFileUtil;
import com.tencent.tinker.loader.shareutil.ShareSecurityCheck;
import com.tencent.tinker.loader.shareutil.ShareTinkerInternals;
import com.tencent.tinker.loader.shareutil.ShareTinkerLog;
import com.tencent.tinker.ziputils.ziputil.AlignedZipOutputStream;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Created by zhangshaowen on 16/4/12.
 */
public class DexDiffPatchInternal extends BasePatchInternal {
    protected static final String TAG = "Tinker.DexDiffPatchInternal";

    protected static final int WAIT_ASYN_OAT_TIME = 10 * 1000;
    protected static final int MAX_WAIT_COUNT     = 120;


    private static ArrayList<File>                      optFiles      = new ArrayList<>();
    // dex_meta中差异dex信息
    private static ArrayList<ShareDexDiffPatchInfo>     patchList     = new ArrayList<>();
    private static HashMap<ShareDexDiffPatchInfo, File> classNDexInfo = new HashMap<>();
    private static boolean                              isVmArt       = ShareTinkerInternals.isVmArt();


    protected static boolean tryRecoverDexFiles(Tinker manager, ShareSecurityCheck checker, Context context,
                                                String patchVersionDirectory, File patchFile, PatchResult patchResult) {
        if (!manager.isEnabledForDex()) {
            ShareTinkerLog.w(TAG, "patch recover, dex is not enabled");
            return true;
        }
        String dexMeta = checker.getMetaContentMap().get(DEX_META_FILE);

        if (dexMeta == null) {
            ShareTinkerLog.w(TAG, "patch recover, dex is not contained");
            return true;
        }

        long begin = SystemClock.elapsedRealtime();
        // 合成dex
        boolean result = patchDexExtractViaDexDiff(context, patchVersionDirectory, dexMeta, patchFile, patchResult);
        long cost = SystemClock.elapsedRealtime() - begin;
        ShareTinkerLog.i(TAG, "recover dex result:%b, cost:%d", result, cost);
        return result;
    }

    protected static boolean waitAndCheckDexOptFile(File patchFile, Tinker manager) {
        if (optFiles.isEmpty()) {
            return true;
        }
        // should use patch list size
        int size = patchList.size() * 30;
        if (size > MAX_WAIT_COUNT) {
            size = MAX_WAIT_COUNT;
        }
        ShareTinkerLog.i(TAG, "raw dex count: %d, dex opt dex count: %d, final wait times: %d", patchList.size(), optFiles.size(), size);

        for (int i = 0; i < size; i++) {
            if (!checkAllDexOptFile(optFiles, i + 1)) {
                try {
                    Thread.sleep(WAIT_ASYN_OAT_TIME);
                } catch (InterruptedException e) {
                    ShareTinkerLog.e(TAG, "thread sleep InterruptedException e:" + e);
                }
            }
        }
        List<File> failDexFiles = new ArrayList<>();
        // check again, if still can't be found, just return
        for (File file : optFiles) {
            ShareTinkerLog.i(TAG, "check dex optimizer file exist: %s, size %d", file.getPath(), file.length());

            if (!SharePatchFileUtil.isLegalFile(file) && !SharePatchFileUtil.shouldAcceptEvenIfIllegal(file)) {
                ShareTinkerLog.e(TAG, "final parallel dex optimizer file %s is not exist, return false", file.getName());
                failDexFiles.add(file);
            }
        }
        if (!failDexFiles.isEmpty()) {
            manager.getPatchReporter().onPatchDexOptFail(patchFile, failDexFiles,
                new TinkerRuntimeException(ShareConstants.CHECK_DEX_OAT_EXIST_FAIL));
            return false;
        }
        if (Build.VERSION.SDK_INT >= 21) {
            Throwable lastThrowable = null;
            for (File file : optFiles) {
                if (SharePatchFileUtil.shouldAcceptEvenIfIllegal(file)) {
                    continue;
                }
                ShareTinkerLog.i(TAG, "check dex optimizer file format: %s, size %d", file.getName(), file.length());
                int returnType;
                try {
                    returnType = ShareElfFile.getFileTypeByMagic(file);
                } catch (IOException e) {
                    // read error just continue
                    continue;
                }
                if (returnType == ShareElfFile.FILE_TYPE_ELF) {
                    ShareElfFile elfFile = null;
                    try {
                        elfFile = new ShareElfFile(file);
                    } catch (Throwable e) {
                        ShareTinkerLog.e(TAG, "final parallel dex optimizer file %s is not elf format, return false", file.getName());
                        failDexFiles.add(file);
                        lastThrowable = e;
                    } finally {
                        IOHelper.closeQuietly(elfFile);
                    }
                }
            }
            if (!failDexFiles.isEmpty()) {
                Throwable returnThrowable = lastThrowable == null
                    ? new TinkerRuntimeException(ShareConstants.CHECK_DEX_OAT_FORMAT_FAIL)
                    : new TinkerRuntimeException(ShareConstants.CHECK_DEX_OAT_FORMAT_FAIL, lastThrowable);

                manager.getPatchReporter().onPatchDexOptFail(patchFile, failDexFiles,
                    returnThrowable);
                return false;
            }
        }
        return true;
    }

    private static boolean patchDexExtractViaDexDiff(Context context, String patchVersionDirectory, String meta, final File patchFile, PatchResult patchResult) {
        // data/data/包名/tinker/patch-xxx/dex
        String dir = patchVersionDirectory + "/" + DEX_PATH + "/";
        // 合成dex
        if (!extractDexDiffInternals(context, dir, meta, patchFile, TYPE_DEX)) {
            ShareTinkerLog.w(TAG, "patch recover, extractDiffInternals fail");
            return false;
        }

        File dexFiles = new File(dir);
        File[] files = dexFiles.listFiles();
        // 存放合成结果文件
        List<File> legalFiles = new ArrayList<>();
        if (files != null) {
            for (File file : files) {
                final String fileName = file.getName();
                // may have directory in android o
                if (file.isFile()
                    &&  (fileName.endsWith(ShareConstants.DEX_SUFFIX)
                      || fileName.endsWith(ShareConstants.JAR_SUFFIX)
                      || fileName.endsWith(ShareConstants.PATCH_SUFFIX))
                ) {
                    legalFiles.add(file);
                }
            }
        }

        ShareTinkerLog.i(TAG, "legal files to do dexopt: " + legalFiles);
        // 存放dexopt产物，data/data/包名/tinker/patch-xxx/odex
        final String optimizeDexDirectory = patchVersionDirectory + "/" + DEX_OPTIMIZE_PATH + "/";
        // 触发执行dexopt
        return dexOptimizeDexFiles(context, legalFiles, optimizeDexDirectory, patchFile, patchResult);
    }

    private static boolean checkClassNDexFiles(final String dexFilePath) {
       if (patchList.isEmpty() || !isVmArt) {
            return false;
        }
        ShareDexDiffPatchInfo testInfo = null;
        File testFile = null;
        // 遍历dex文件信息，过滤出补丁包中所有classesN.dex文件，并将test.dex文件重命名为classesN.dex插入到最后面
        for (ShareDexDiffPatchInfo info : patchList) {
            File dexFile = new File(dexFilePath + info.realName);
            String fileName = dexFile.getName();

            if (ShareConstants.CLASS_N_PATTERN.matcher(fileName).matches()) {
                classNDexInfo.put(info, dexFile);
            }
            if (info.rawName.startsWith(ShareConstants.TEST_DEX_NAME)) {
                testInfo = info;
                testFile = dexFile;
            }
        }
        if (testInfo != null) {
            classNDexInfo.put(ShareTinkerInternals.changeTestDexToClassN(testInfo, classNDexInfo.size() + 1), testFile);
        }
        // data/data/包名/tinker/patch-xxx/dex/tinker_classN.apk
        // 此文件用于存放补丁包中所有的classesN.dex文件
        File classNFile = new File(dexFilePath, ShareConstants.CLASS_N_APK_NAME);
        boolean result = true;
        // 如果tinker_classN.apk已经存在，这里会遍历其中的每个dex文件
        // 如果有任何一个dex和当前要合成的补丁中对应的预合成dex md5校验失败，则删除tinker_classN.apk
        if (classNFile.exists()) {
            for (ShareDexDiffPatchInfo info : classNDexInfo.keySet()) {
                if (!SharePatchFileUtil.verifyDexFileMd5(classNFile, info.rawName, info.destMd5InArt)) {
                    ShareTinkerLog.e(TAG, "verify dex file md5 error, entry name; %s, file len: %d", info.rawName, classNFile.length());
                    result = false;
                    break;
                }
            }
            if (!result) {
                SharePatchFileUtil.safeDeleteFile(classNFile);
            }
        } else {
            result = false;
        }
        // 如果tinker_classN.apk已经存在并校验通过，则不需要将补丁包中classesN.dex合成为tinker_classN.apk，将所有dex删除即可
        if (result) {
            // delete classN dex if exist
            for (File dexFile : classNDexInfo.values()) {
                SharePatchFileUtil.safeDeleteFile(dexFile);
            }
        }

        return result;
    }

    private static ZipEntry makeStoredZipEntry(ZipEntry originalEntry, String realDexName) {
        final ZipEntry result = new ZipEntry(realDexName);
        result.setMethod(ZipEntry.STORED);
        result.setCompressedSize(originalEntry.getSize());
        result.setSize(originalEntry.getSize());
        result.setCrc(originalEntry.getCrc());
        return result;
    }

    private static boolean mergeClassNDexFiles(final Context context, final File patchFile, final String dexFilePath) {
        // only merge for art vm
        if (patchList.isEmpty() || !isVmArt) {
            return true;
        }
        // data/data/包名/tinker/patch-xxx/dex/tinker_classN.apk
        File classNFile = new File(dexFilePath, ShareConstants.CLASS_N_APK_NAME);

        // repack just more than one classN.dex
        if (classNDexInfo.isEmpty()) {
            ShareTinkerLog.w(TAG, "classNDexInfo size: %d, no need to merge classN dex files", classNDexInfo.size());
            return true;
        }
        long start = System.currentTimeMillis();
        boolean result = true;
        AlignedZipOutputStream out = null;
        try {
            out = new AlignedZipOutputStream(new BufferedOutputStream(new FileOutputStream(classNFile)));
            for (ShareDexDiffPatchInfo info : classNDexInfo.keySet()) {
                File dexFile = classNDexInfo.get(info);
                if (info.isJarMode) {
                    ZipFile dexZipFile = null;
                    InputStream inputStream = null;
                    try {
                        dexZipFile = new ZipFile(dexFile);
                        ZipEntry rawDexZipEntry = dexZipFile.getEntry(ShareConstants.DEX_IN_JAR);
                        ZipEntry newDexZipEntry = makeStoredZipEntry(rawDexZipEntry, info.rawName);
                        inputStream = dexZipFile.getInputStream(rawDexZipEntry);
                        try {
                            out.putNextEntry(newDexZipEntry);
                            IOHelper.copyStream(inputStream, out);
                        } finally {
                            out.closeEntry();
                        }
                    } finally {
                        IOHelper.closeQuietly(inputStream);
                        IOHelper.closeQuietly(dexZipFile);
                    }
                } else {
                    ZipEntry newDexZipEntry = new ZipEntry(info.rawName);
                    newDexZipEntry.setMethod(ZipEntry.STORED);
                    newDexZipEntry.setCompressedSize(dexFile.length());
                    newDexZipEntry.setSize(dexFile.length());
                    newDexZipEntry.setCrc(DigestUtil.getCRC32(dexFile));

                    InputStream is = null;
                    try {
                        is = new BufferedInputStream(new FileInputStream(dexFile));
                        try {
                            out.putNextEntry(newDexZipEntry);
                            IOHelper.copyStream(is, out);
                        } finally {
                            out.closeEntry();
                        }
                    } finally {
                        IOHelper.closeQuietly(is);
                    }
                }
            }
        } catch (Throwable throwable) {
            ShareTinkerLog.printErrStackTrace(TAG, throwable, "merge classN file");
            result = false;
        } finally {
            IOHelper.closeQuietly(out);
        }

        if (result) {
            for (ShareDexDiffPatchInfo info : classNDexInfo.keySet()) {
                if (!SharePatchFileUtil.verifyDexFileMd5(classNFile, info.rawName, info.destMd5InArt)) {
                    result = false;
                    ShareTinkerLog.e(TAG, "verify dex file md5 error, entry name; %s, file len: %d", info.rawName, classNFile.length());
                    break;
                }
            }
        }
        if (result) {
            for (File dexFile : classNDexInfo.values()) {
                SharePatchFileUtil.safeDeleteFile(dexFile);
            }
        } else {
            ShareTinkerLog.e(TAG, "merge classN dex error, try delete temp file");
            SharePatchFileUtil.safeDeleteFile(classNFile);
            Tinker.with(context).getPatchReporter().onPatchTypeExtractFail(patchFile, classNFile, classNFile.getName(), TYPE_CLASS_N_DEX);
        }
        ShareTinkerLog.i(TAG, "merge classN dex file %s, result: %b, size: %d, use: %dms",
            classNFile.getPath(), result, classNFile.length(), (System.currentTimeMillis() - start));
        return result;
    }

    private static boolean dexOptimizeDexFiles(Context context, List<File> dexFiles, String optimizeDexDirectory, final File patchFile, final PatchResult patchResult) {
        final Tinker manager = Tinker.with(context);
        optFiles.clear();
        if (dexFiles != null) {
            // data/data/包名/tinker/patch-xxx/odex
            File optimizeDexDirectoryFile = new File(optimizeDexDirectory);
            if (!optimizeDexDirectoryFile.exists() && !optimizeDexDirectoryFile.mkdirs()) {
                ShareTinkerLog.w(TAG, "patch recover, make optimizeDexDirectoryFile fail");
                return false;
            }
            // add opt files
            for (File file : dexFiles) {
                // 获取dexopt产物输出路径
                // android8.0后是data/data/包名/tinker/patch-xxx/oat/<isa>/xxx.odex
                // 8.0前是data/data/包名/tinker/patch-xxx/odex/xxx.dex
                String outputPathName = SharePatchFileUtil.optimizedPathFor(file, optimizeDexDirectoryFile);
                optFiles.add(new File(outputPathName));
            }

            final List<File> failOptDexFile = new Vector<>();
            final Throwable[] throwable = new Throwable[1];

            if (patchResult != null) {
                patchResult.dexoptTriggerTime = System.currentTimeMillis();
            }
            // 是否使用DelegateLastClassLoader类
            final boolean useDLC = TinkerApplication.getInstance().isUseDelegateLastClassLoader();
            final boolean[] anyOatNotGenerated = {false};

            // try parallel dex optimizer
            // 开始并行dexopt
            TinkerDexOptimizer.optimizeAll(
                  context, dexFiles, optimizeDexDirectoryFile,
                  useDLC,
                  new TinkerDexOptimizer.ResultCallback() {
                      long startTime;

                      @Override
                      public void onStart(File dexFile, File optimizedDir) {
                          startTime = System.currentTimeMillis();
                          ShareTinkerLog.i(TAG, "start to parallel optimize dex %s, size: %d", dexFile.getPath(), dexFile.length());
                      }

                      @Override
                      public void onSuccess(File dexFile, File optimizedDir, File optimizedFile) {
                          ShareTinkerLog.i(TAG, "success to parallel optimize dex %s, opt file:%s, opt file size: %d, use time %d",
                              dexFile.getPath(), optimizedFile.getPath(), optimizedFile.length(), (System.currentTimeMillis() - startTime));
                          if (!optimizedFile.exists()) {
                              synchronized (anyOatNotGenerated) {
                                  anyOatNotGenerated[0] = true;
                              }
                          }
                      }

                      @Override
                      public void onFailed(File dexFile, File optimizedDir, Throwable thr) {
                          ShareTinkerLog.i(TAG, "fail to parallel optimize dex %s use time %d",
                              dexFile.getPath(), (System.currentTimeMillis() - startTime));
                          failOptDexFile.add(dexFile);
                          throwable[0] = thr;
                      }
                  }
            );

            if (patchResult != null) {
                synchronized (anyOatNotGenerated) {
                    patchResult.isOatGenerated = !anyOatNotGenerated[0];
                }
            }

            if (!failOptDexFile.isEmpty()) {
                manager.getPatchReporter().onPatchDexOptFail(patchFile, failOptDexFile, throwable[0]);
                return false;
            }
        }
        return true;
    }

    /**
     * for ViVo or some other rom, they would make dex2oat asynchronous
     * so we need to check whether oat file is actually generated.
     *
     * @param files
     * @param count
     * @return
     */
    private static boolean checkAllDexOptFile(ArrayList<File> files, int count) {
        for (File file : files) {
            if (!SharePatchFileUtil.isLegalFile(file)) {
                if (SharePatchFileUtil.shouldAcceptEvenIfIllegal(file)) {
                    continue;
                }
                ShareTinkerLog.e(TAG, "parallel dex optimizer file %s is not exist, just wait %d times", file.getName(), count);
                return false;
            }
        }
        return true;
    }

    private static boolean extractDexDiffInternals(Context context, String dir, String meta, File patchFile, int type) {
        //parse
        patchList.clear();
        // 解析dex_meta文件，结果装入patchList
        ShareDexDiffPatchInfo.parseDexDiffPatchInfo(meta, patchList);

        if (patchList.isEmpty()) {
            ShareTinkerLog.w(TAG, "extract patch list is empty! type:%s:", ShareTinkerInternals.getTypeString(type));
            return true;
        }
        // data/data/包名/tinker/patch-xxx/dex
        File directory = new File(dir);
        if (!directory.exists()) {
            directory.mkdirs();
        }
        //I think it is better to extract the raw files from apk
        Tinker manager = Tinker.with(context);
        ZipFile apk = null;
        ZipFile patch = null;
        try {
            ApplicationInfo applicationInfo = context.getApplicationInfo();
            if (applicationInfo == null) {
                // Looks like running on a test Context, so just return without patching.
                ShareTinkerLog.w(TAG, "applicationInfo == null!!!!");
                return false;
            }

            String apkPath = applicationInfo.sourceDir;
            apk = new ZipFile(apkPath);
            patch = new ZipFile(patchFile);
            // art下合成补丁，合成所有old dex和patch dex，然后打包为tinker_classN.apk，dalvik下不打包dex
            // 判断是否需要生成tinker_classN.apk文件
            if (checkClassNDexFiles(dir)) {
                ShareTinkerLog.w(TAG, "class n dex file %s is already exist, and md5 match, just continue", ShareConstants.CLASS_N_APK_NAME);
                return true;
            }
            for (ShareDexDiffPatchInfo info : patchList) {
                long start = System.currentTimeMillis();

                final String infoPath = info.path;
                String patchRealPath;
                if (infoPath.equals("")) {
                    patchRealPath = info.rawName;
                } else {
                    patchRealPath = info.path + "/" + info.rawName;
                }

                String dexDiffMd5 = info.dexDiffMd5;
                String oldDexCrc = info.oldDexCrC;
                // 非主dex，且该dex没有改变的话destMd5InDvm字段值为"0"，此dex在art下无需合成
                if (!isVmArt && info.destMd5InDvm.equals("0")) {
                    ShareTinkerLog.w(TAG, "patch dex %s is only for art, just continue", patchRealPath);
                    continue;
                }
                String extractedFileMd5 = isVmArt ? info.destMd5InArt : info.destMd5InDvm;

                if (!SharePatchFileUtil.checkIfMd5Valid(extractedFileMd5)) {
                    ShareTinkerLog.w(TAG, "meta file md5 invalid, type:%s, name: %s, md5: %s", ShareTinkerInternals.getTypeString(type), info.rawName, extractedFileMd5);
                    manager.getPatchReporter().onPatchPackageCheckFail(patchFile, BasePatchInternal.getMetaCorruptedCode(type));
                    return false;
                }
                // data/data/包名/tinker/patch-xxx/dex/dex名称，用于存放合成后的dex
                File extractedFile = new File(dir + info.realName);

                // 检查合成后的dex（此时还未合成，如果存在说明之前已经合成过该dex）是否已经存在，存在说明已经合成过该dex
                // 已经存在则要验证是否和补丁包中记录的预合成的dex的md5一致性，不一致需要删除已存在的dex
                if (extractedFile.exists()) {
                    if (SharePatchFileUtil.verifyDexFileMd5(extractedFile, extractedFileMd5)) {
                        //it is ok, just continue
                        ShareTinkerLog.w(TAG, "dex file %s is already exist, and md5 match, just continue", extractedFile.getPath());
                        continue;
                    } else {
                        ShareTinkerLog.w(TAG, "have a mismatch corrupted dex " + extractedFile.getPath());
                        extractedFile.delete();
                    }
                } else {
                    extractedFile.getParentFile().mkdirs();
                }
                // 补丁包中patch dex
                ZipEntry patchFileEntry = patch.getEntry(patchRealPath);
                // old dex
                ZipEntry rawApkFileEntry = apk.getEntry(patchRealPath);
                if (oldDexCrc.equals("0")) {
                    // oldDexCrc为"0"表明该dex是新增的
                    if (patchFileEntry == null) {
                        ShareTinkerLog.w(TAG, "patch entry is null. path:" + patchRealPath);
                        manager.getPatchReporter().onPatchTypeExtractFail(patchFile, extractedFile, info.rawName, type);
                        return false;
                    }

                    // 提取补丁包中dex到data/data/包名/tinker/patch-xxx/dex/
                    if (!extractDexFile(patch, patchFileEntry, extractedFile, info)) {
                        ShareTinkerLog.w(TAG, "Failed to extract raw patch file " + extractedFile.getPath());
                        manager.getPatchReporter().onPatchTypeExtractFail(patchFile, extractedFile, info.rawName, type);
                        return false;
                    }
                } else if (dexDiffMd5.equals("0")) {
                    // oldDexCrc不为"0"，dexDiffMd5为"0"代表该dex没有改变
                    // 此情况art下需要将old dex拷贝到补丁dex目录，dalvik下忽略
                    if (!isVmArt) {
                        continue;
                    }

                    if (rawApkFileEntry == null) {
                        ShareTinkerLog.w(TAG, "apk entry is null. path:" + patchRealPath);
                        manager.getPatchReporter().onPatchTypeExtractFail(patchFile, extractedFile, info.rawName, type);
                        return false;
                    }

                    //check source crc instead of md5 for faster
                    String rawEntryCrc = String.valueOf(rawApkFileEntry.getCrc());
                    // old dex crc校验（补丁包中记录的old dex crc和当前apk中old dex crc）
                    if (!rawEntryCrc.equals(oldDexCrc)) {
                        ShareTinkerLog.e(TAG, "apk entry %s crc is not equal, expect crc: %s, got crc: %s", patchRealPath, oldDexCrc, rawEntryCrc);
                        manager.getPatchReporter().onPatchTypeExtractFail(patchFile, extractedFile, info.rawName, type);
                        return false;
                    }

                    // 从当前apk中将old dex复制到data/data/包名/tinker/patch-xxx/dex/
                    extractDexFile(apk, rawApkFileEntry, extractedFile, info);

                    if (!SharePatchFileUtil.verifyDexFileMd5(extractedFile, extractedFileMd5)) {
                        ShareTinkerLog.w(TAG, "Failed to recover dex file when verify patched dex: " + extractedFile.getPath());
                        manager.getPatchReporter().onPatchTypeExtractFail(patchFile, extractedFile, info.rawName, type);
                        SharePatchFileUtil.safeDeleteFile(extractedFile);
                        return false;
                    }
                } else {
                    // 此分支中old dex patch dex都应该存在
                    if (patchFileEntry == null) {
                        ShareTinkerLog.w(TAG, "patch entry is null. path:" + patchRealPath);
                        manager.getPatchReporter().onPatchTypeExtractFail(patchFile, extractedFile, info.rawName, type);
                        return false;
                    }

                    if (!SharePatchFileUtil.checkIfMd5Valid(dexDiffMd5)) {
                        ShareTinkerLog.w(TAG, "meta file md5 invalid, type:%s, name: %s, md5: %s", ShareTinkerInternals.getTypeString(type), info.rawName, dexDiffMd5);
                        manager.getPatchReporter().onPatchPackageCheckFail(patchFile, BasePatchInternal.getMetaCorruptedCode(type));
                        return false;
                    }
                    // 当前apk中old dex是否存在
                    if (rawApkFileEntry == null) {
                        ShareTinkerLog.w(TAG, "apk entry is null. path:" + patchRealPath);
                        manager.getPatchReporter().onPatchTypeExtractFail(patchFile, extractedFile, info.rawName, type);
                        return false;
                    }
                    // old dex crc校验（补丁包中记录的old dex crc和当前apk中old dex crc）
                    String rawEntryCrc = String.valueOf(rawApkFileEntry.getCrc());
                    if (!rawEntryCrc.equals(oldDexCrc)) {
                        ShareTinkerLog.e(TAG, "apk entry %s crc is not equal, expect crc: %s, got crc: %s", patchRealPath, oldDexCrc, rawEntryCrc);
                        manager.getPatchReporter().onPatchTypeExtractFail(patchFile, extractedFile, info.rawName, type);
                        return false;
                    }
                    // 合成补丁，合成完后写入合成结果dex到extractedFile(data/data/包名/tinker/patch-xxx/dex)
                    // 内部通过DexPatchApplier类合成补丁，算法实现相关代码不具体分析
                    patchDexFile(apk, patch, rawApkFileEntry, patchFileEntry, info, extractedFile);
                    // 校验本次合成成功后dex的md5，是否和打补丁包时预合成的md5一致
                    if (!SharePatchFileUtil.verifyDexFileMd5(extractedFile, extractedFileMd5)) {
                        ShareTinkerLog.w(TAG, "Failed to recover dex file when verify patched dex: " + extractedFile.getPath());
                        manager.getPatchReporter().onPatchTypeExtractFail(patchFile, extractedFile, info.rawName, type);
                        SharePatchFileUtil.safeDeleteFile(extractedFile);
                        return false;
                    }

                    ShareTinkerLog.w(TAG, "success recover dex file: %s, size: %d, use time: %d",
                        extractedFile.getPath(), extractedFile.length(), (System.currentTimeMillis() - start));
                }
            }
            // art将所有合成完毕的dex打包为tinker_classN.apk
            if (!mergeClassNDexFiles(context, patchFile, dir)) {
                return false;
            }
        } catch (Throwable e) {
            throw new TinkerRuntimeException("patch " + ShareTinkerInternals.getTypeString(type) + " extract failed (" + e.getMessage() + ").", e);
        } finally {
            SharePatchFileUtil.closeZip(apk);
            SharePatchFileUtil.closeZip(patch);
        }
        return true;
    }

    /**
     * repack dex to jar
     *
     * @param zipFile
     * @param entryFile
     * @param extractTo
     * @param targetMd5
     * @return boolean
     * @throws IOException
     */
    private static boolean extractDexToJar(ZipFile zipFile, ZipEntry entryFile, File extractTo, String targetMd5) throws IOException {
        int numAttempts = 0;
        boolean isExtractionSuccessful = false;
        while (numAttempts < MAX_EXTRACT_ATTEMPTS && !isExtractionSuccessful) {
            numAttempts++;

            ZipOutputStream zos = null;
            BufferedInputStream bis = null;

            ShareTinkerLog.i(TAG, "try Extracting " + extractTo.getPath());
            try {
                zos = new ZipOutputStream(new
                    BufferedOutputStream(new FileOutputStream(extractTo)));
                bis = new BufferedInputStream(zipFile.getInputStream(entryFile));

                byte[] buffer = new byte[ShareConstants.BUFFER_SIZE];
                ZipEntry entry = new ZipEntry(ShareConstants.DEX_IN_JAR);
                zos.putNextEntry(entry);
                int length = bis.read(buffer);
                while (length != -1) {
                    zos.write(buffer, 0, length);
                    length = bis.read(buffer);
                }
                zos.closeEntry();
            } finally {
                IOHelper.closeQuietly(bis);
                IOHelper.closeQuietly(zos);
            }

            isExtractionSuccessful = SharePatchFileUtil.verifyDexFileMd5(extractTo, targetMd5);
            ShareTinkerLog.i(TAG, "isExtractionSuccessful: %b", isExtractionSuccessful);

            if (!isExtractionSuccessful) {
                final boolean succ = extractTo.delete();
                if (!succ || extractTo.exists()) {
                    ShareTinkerLog.e(TAG, "Failed to delete corrupted dex " + extractTo.getPath());
                }
            }
        }
        return isExtractionSuccessful;
    }

    // /**
    //  * reject dalvik vm, but sdk version is larger than 21
    //  */
    // private static void checkVmArtProperty() {
    //     boolean art = ShareTinkerInternals.isVmArt();
    //     if (!art && Build.VERSION.SDK_INT >= 21) {
    //         throw new TinkerRuntimeException(ShareConstants.CHECK_VM_PROPERTY_FAIL + ", it is dalvik vm, but sdk version " + Build.VERSION.SDK_INT + " is larger than 21!");
    //     }
    // }

    private static boolean extractDexFile(ZipFile zipFile, ZipEntry entryFile, File extractTo, ShareDexDiffPatchInfo dexInfo) throws IOException {
        final String fileMd5 = isVmArt ? dexInfo.destMd5InArt : dexInfo.destMd5InDvm;
        final String rawName = dexInfo.rawName;
        final boolean isJarMode = dexInfo.isJarMode;
        //it is raw dex and we use jar mode, so we need to zip it!
        if (SharePatchFileUtil.isRawDexFile(rawName) && isJarMode) {
            return extractDexToJar(zipFile, entryFile, extractTo, fileMd5);
        }
        return extract(zipFile, entryFile, extractTo, fileMd5, true);
    }

    /**
     * Generate patched dex file (May wrapped it by a jar if needed.)
     *
     * @param baseApk        OldApk.
     * @param patchPkg       Patch package, it is also a zip file.
     * @param oldDexEntry    ZipEntry of old dex.
     * @param patchFileEntry ZipEntry of patch file. (also ends with .dex) This could be null.
     * @param patchInfo      Parsed patch info from package-meta.txt
     * @param patchedDexFile Patched dex file, may be a jar.
     *                       <p>
     *                       <b>Notice: patchFileEntry and smallPatchInfoFile cannot both be null.</b>
     * @throws IOException
     */
    private static void patchDexFile(
        ZipFile baseApk, ZipFile patchPkg, ZipEntry oldDexEntry, ZipEntry patchFileEntry,
        ShareDexDiffPatchInfo patchInfo, File patchedDexFile) throws IOException {
        InputStream oldDexStream = null;
        InputStream patchFileStream = null;
        try {
            oldDexStream = new BufferedInputStream(baseApk.getInputStream(oldDexEntry));
            patchFileStream = (patchFileEntry != null ? new BufferedInputStream(patchPkg.getInputStream(patchFileEntry)) : null);

            final boolean isRawDexFile = SharePatchFileUtil.isRawDexFile(patchInfo.rawName);
            if (!isRawDexFile || patchInfo.isJarMode) {
                ZipOutputStream zos = null;
                try {
                    zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(patchedDexFile)));
                    zos.putNextEntry(new ZipEntry(ShareConstants.DEX_IN_JAR));
                    // Old dex is not a raw dex file.
                    if (!isRawDexFile) {
                        // 是jar文件则从中读取dex
                        ZipInputStream zis = null;
                        try {
                            zis = new ZipInputStream(oldDexStream);
                            ZipEntry entry;
                            while ((entry = zis.getNextEntry()) != null) {
                                if (ShareConstants.DEX_IN_JAR.equals(entry.getName())) break;
                            }
                            if (entry == null) {
                                throw new TinkerRuntimeException("can't recognize zip dex format file:" + patchedDexFile.getAbsolutePath());
                            }
                            new DexPatchApplier(zis, patchFileStream).executeAndSaveTo(zos);
                        } finally {
                            IOHelper.closeQuietly(zis);
                        }
                    } else {
                        new DexPatchApplier(oldDexStream, patchFileStream).executeAndSaveTo(zos);
                    }
                    zos.closeEntry();
                } finally {
                    IOHelper.closeQuietly(zos);
                }
            } else {
                new DexPatchApplier(oldDexStream, patchFileStream).executeAndSaveTo(patchedDexFile);
            }
        } finally {
            IOHelper.closeQuietly(oldDexStream);
            IOHelper.closeQuietly(patchFileStream);
        }
    }

}
