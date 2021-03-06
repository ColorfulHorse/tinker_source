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

package com.tencent.tinker.lib.tinker;

import android.content.Context;

import com.tencent.tinker.entry.ApplicationLike;
import com.tencent.tinker.lib.listener.PatchListener;
import com.tencent.tinker.lib.patch.AbstractPatch;
import com.tencent.tinker.lib.reporter.LoadReporter;
import com.tencent.tinker.lib.reporter.PatchReporter;
import com.tencent.tinker.lib.service.AbstractResultService;
import com.tencent.tinker.loader.shareutil.ShareTinkerLog;

/**
 * Created by zhangshaowen on 16/3/19.
 */
public class TinkerInstaller {
    private static final String TAG = "Tinker.TinkerInstaller";

    /**
     * install tinker with default config, you must install tinker before you use their api
     * or you can just use {@link TinkerApplicationHelper}'s api
     *
     * @param applicationLike
     */
    public static Tinker install(ApplicationLike applicationLike) {
        Tinker tinker = new Tinker.Builder(applicationLike.getApplication()).build();
        Tinker.create(tinker);
        tinker.install(applicationLike.getTinkerResultIntent());
        return tinker;
    }

    /**
     * 需要调用tinker.install后才能使用tinker api，否则只能使用TinkerApplicationHelper中的api
     * @param applicationLike  application代理
     * @param loadReporter  加载补丁的回调类，默认DefaultLoadReporter
     * @param patchReporter 合成补丁的回调类，默认DefaultPatchReporter
     * @param listener  接收合成补丁任务的类，默认DefaultPatchListener
     * @param resultServiceClass  patch补丁合成进程将合成结果返回给主进程的类，默认DefaultTinkerResultService
     * @param upgradePatchProcessor  执行补丁合成操作的类，默认UpgradePatch
     */
    public static Tinker install(ApplicationLike applicationLike, LoadReporter loadReporter, PatchReporter patchReporter,
                                 PatchListener listener, Class<? extends AbstractResultService> resultServiceClass,
                                 AbstractPatch upgradePatchProcessor) {
        // 创建实例，注册一些回调
        Tinker tinker = new Tinker.Builder(applicationLike.getApplication())
            .tinkerFlags(applicationLike.getTinkerFlags())
            .loadReport(loadReporter)
            .listener(listener)
            .patchReporter(patchReporter)
            // 加载补丁是否校验md5
            .tinkerLoadVerifyFlag(applicationLike.getTinkerLoadVerifyFlag()).build();

        Tinker.create(tinker);
        // getTinkerResultIntent得到的是此次启动加载补丁的结果信息
        tinker.install(applicationLike.getTinkerResultIntent(), resultServiceClass, upgradePatchProcessor);
        return tinker;
    }

    /**
     * clean all patch files!
     *
     * @param context
     */
    public static void cleanPatch(Context context) {
        Tinker.with(context).cleanPatch();
    }

    /**
     * new patch file to install, try install them with :patch process
     *
     * @param context
     * @param patchLocation
     */
    public static void onReceiveUpgradePatch(Context context, String patchLocation) {
        Tinker.with(context).getPatchListener().onPatchReceived(patchLocation);
    }

    /**
     * set logIml for ShareTinkerLog
     *
     * @param imp
     */
    public static void setLogIml(ShareTinkerLog.TinkerLogImp imp) {
        ShareTinkerLog.setTinkerLogImp(imp);
    }
}
