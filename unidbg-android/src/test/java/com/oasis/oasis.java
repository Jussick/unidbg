package com.oasis;

// 导入通用且标准的类库
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import com.zdcode.BaseApp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

// 继承AbstractJni类
public class oasis extends BaseApp {
    oasis() {
        super();
        processName = "com.sina.oasis";
        apkPath = "unidbg-android/src/test/resources/example_binaries/oasis/lvzhou.apk";
        soPath = "unidbg-android/src/test/resources/example_binaries/oasis/liboasiscore.so";
        sdkVersion = 19;
        beginInit();
        endInit();
    };

    public static void main(String[] args) {
        oasis test = new oasis();
        test.hookMd5Update();
        System.out.println(test.getS());
    }

    public String getS(){
        // args list
        List<Object> list = new ArrayList<>(10);
        // arg1 env
        list.add(vm.getJNIEnv());
        // arg2 jobject/jclazz 一般用不到，直接填0
        list.add(0);
        // arg3 bytes
        String input = "aid=01A-khBWIm48A079Pz_DMW6PyZR8" +
                "uyTumcCNm4e8awxyC2ANU.&cfrom=28B529501" +
                "0&cuid=5999578300&noncestr=46274W9279Hr1" +
                "X49A5X058z7ZVz024&platform=ANDROID&timestamp" +
                "=1621437643609&ua=Xiaomi-MIX2S__oasis__3.5.8_" +
                "_Android__Android10&version=3.5.8&vid=10190135" +
                "94003&wm=20004_90024";
        byte[] inputByte = input.getBytes(StandardCharsets.UTF_8);
        ByteArray inputByteArray = new ByteArray(vm,inputByte);
        list.add(vm.addLocalObject(inputByteArray));
        // arg4 ,boolean false 填入0
        list.add(0);
        // 参数准备完成
        // call function
        Number number = module.callFunction(emulator, 0xC365, list.toArray());
        String result = vm.getObject(number.intValue()).getValue().toString();
        return result;
    }

    public void hookMd5Update(){
        hook(module.base + 0x8AB2 + 1, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext context = emulator.getContext();
                Pointer input = context.getPointerArg(1);
                int length = context.getIntArg(2);

                Inspector.inspect(input.getByteArray(0, length), "arg1");
                // OnLeave
                hook(context.getLRPointer().peer, new BreakPointCallback() {
                    @Override
                    public boolean onHit(Emulator<?> emulator, long address) {
                        return true;
                    }
                });
                return true;
            }
        });
    }
}
