package com.calculateS;

// 导入通用且标准的类库

import com.github.unidbg.Emulator;
import com.github.unidbg.TraceHook;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.HookZzArm32RegisterContext;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VarArg;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import com.zdcode.BaseApp;

import java.util.ArrayList;
import java.util.List;

public class sina extends BaseApp {
    sina() {
        super();
        processName = "com.sina.International";
        apkPath = "unidbg-android/src/test/resources/example_binaries/calculateS/sinaInternational.apk";
        soPath = "unidbg-android/src/test/resources/example_binaries/calculateS/libutility.so";
        init();
    };

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "android/content/ContextWrapper->getPackageManager()Landroid/content/pm/PackageManager;":
                return vm.resolveClass("android/content/pm/PackageManager").newObject(signature);
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    public String calculateS(){
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        list.add(0); // 第二个参数，实例方法是jobject，静态方法是jclazz，直接填0，一般用不到。
        //这里传android/content/Context不行，是因为调用callObjectMethod之前查询android/content/Context的函数map为空，函数只有经过GetMethodID才会被创建放入函数map
        //so的代码里是通过android/content/ContextWrapper调用的GetMethodID,所以函数被填充到了这个类的函数map中
        DvmObject<?> context = vm.resolveClass("android/content/ContextWrapper").newObject(null);// context
        list.add(vm.addLocalObject(context));
        list.add(vm.addLocalObject(new StringObject(vm, "A")));
        list.add(vm.addLocalObject(new StringObject(vm, "")));

        Number number = module.callFunction(emulator, 0x1E7C + 1, list.toArray());
        String result = vm.getObject(number.intValue()).getValue().toString();
        return result;
    };

    public void patchVerify(){
        int patchCode = 0x4FF00100; //
        patch(0x1E86, patchCode, new byte[]{ (byte)0xFF, (byte) 0xF7, (byte) 0xEB, (byte) 0xFE });
    }

    public void patchVerify1(){
        patch(0x1E86, "mov r0,1", new byte[]{ (byte)0xFF, (byte) 0xF7, (byte) 0xEB, (byte) 0xFE });
    };

    public void hookMDStringold(){
        hook(0x1BD0 + 1, new WrapCallback<HookZzArm32RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer input = ctx.getPointerArg(0);
                Inspector.inspect(input.getByteArray(0, 34), "arg1");
            }
            @Override
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer result = ctx.getPointerArg(0);
                Inspector.inspect(result.getByteArray(0, 34), "result");
            }
        });
    }

    public void hookMDString(){
        hook(module.base + 0x1BD0, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext context = emulator.getContext();
                final TraceHook th = trace(0, module.size);
                hook(context.getLRPointer().peer, new BreakPointCallback() {
                    @Override
                    public boolean onHit(Emulator<?> emulator, long address) {
                        if (th != null){
                            th.stopTrace();
                            return true;
                        }
                        return false;
                    }
                });
                return true;
            }
        });
    }

    public void hook1C60(){
        hook(module.base + 0x1C60, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext context = emulator.getContext();
                hook(context.getLRPointer().peer, new BreakPointCallback() {
                    @Override
                    public boolean onHit(Emulator<?> emulator, long address) {
                        hookMDString();
                        return true;
                    }
                });
                return true;
            }
        });
    }

    public static void main(String[] args) {
        sina test = new sina();
        //test.patchVerify();
        test.patchVerify1();
        test.hookMDStringold();
        //test.breakPoint(0x1BD0);
        //test.trace(0x1BD0, 0x1C50);
        //test.hook1C60();
        System.out.println(test.calculateS());
    }
}

