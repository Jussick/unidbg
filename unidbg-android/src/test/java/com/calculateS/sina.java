package com.calculateS;

// 导入通用且标准的类库
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.hook.hookzz.*;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import com.zdcode.BaseApp;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class sina extends BaseApp {
    sina() {
        super("com.sina.International",
                "unidbg-android/src/test/resources/example_binaries/calculateS/sinaInternational.apk",
                "unidbg-android/src/test/resources/example_binaries/calculateS/libutility.so");
    };

    public String calculateS(){
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        list.add(0); // 第二个参数，实例方法是jobject，静态方法是jclazz，直接填0，一般用不到。
        DvmClass ctxClazz = vm.resolveClass("android/content/ContextWrapper");
        //ctxClazz.getMethodID("getPackageManager", "()Landroid/content/pm/PackageManager");
        DvmObject<?> context = vm.resolveClass("android/content/ContextWrapper").newObject(null);// context
        list.add(vm.addLocalObject(context));
        list.add(vm.addLocalObject(new StringObject(vm, "12345")));
        list.add(vm.addLocalObject(new StringObject(vm, "r0ysue")));

        Number number = module.callFunction(emulator, 0x1E7C + 1, list.toArray());
        String result = vm.getObject(number.intValue()).getValue().toString();
        return result;
    };

    public void patchVerify(){
        int patchCode = 0x4FF00100; //
        emulator.getMemory().pointer(module.base + 0x1E86).setInt(0,patchCode);
    }

    public void patchVerify1(){
        Pointer pointer = UnidbgPointer.pointer(emulator, module.base + 0x1E86);
        assert pointer != null;
        byte[] code = pointer.getByteArray(0, 4);
        if (!Arrays.equals(code, new byte[]{ (byte)0xFF, (byte) 0xF7, (byte) 0xEB, (byte) 0xFE })) { // BL sub_1C60
            throw new IllegalStateException(Inspector.inspectString(code, "patch32 code=" + Arrays.toString(code)));
        }
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb)) {
            KeystoneEncoded encoded = keystone.assemble("mov r0,1");
            byte[] patch = encoded.getMachineCode();
            if (patch.length != code.length) {
                throw new IllegalStateException(Inspector.inspectString(patch, "patch32 length=" + patch.length));
            }
            pointer.write(0, patch, 0, patch.length);
        }
    };

    public void HookMDStringold(){
        // 加载HookZz
        IHookZz hookZz = HookZz.getInstance(emulator);

        hookZz.wrap(module.base + 0x1BD0 + 1, new WrapCallback<HookZzArm32RegisterContext>() { // inline wrap导出函数
            @Override
            // 类似于 frida onEnter
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                // 类似于Frida args[0]
                Pointer input = ctx.getPointerArg(0);
                System.out.println("input:" + input.getString(0));
            };

            @Override
            // 类似于 frida onLeave
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer result = ctx.getPointerArg(0);
                System.out.println("input:" + result.getString(0));
            }
        });
    }

    public static void main(String[] args) {
        sina test = new sina();
//        test.patchVerify();
        //test.patchVerify1();
        //test.HookMDStringold();
        System.out.println(test.calculateS());
    }
}
