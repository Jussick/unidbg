package com.v2sign;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.hook.hookzz.*;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import com.zdcode.BaseApp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class zuiyou extends BaseApp {
    zuiyou() {
        super("com.xiaochuankeji.tieba",
                "unidbg-android/src/test/resources/example_binaries/v2sign/right573.apk",
                "unidbg-android/src/test/resources/example_binaries/v2sign/libnet_crypto.so",
                19);
        init()/*.dump()*/.build();
    };

    public void native_init(){
        // 0x4a069
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        list.add(0); // 第二个参数，实例方法是jobject，静态方法是jclass，直接填0，一般用不到。
        module.callFunction(emulator, 0x4a069, list.toArray());
    };

    private String callSign(){
        // 准备入参
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        list.add(0); // 第二个参数，实例方法是jobject，静态方法是jclass，直接填0，一般用不到。
        list.add(vm.addLocalObject(new StringObject(vm, "12345")));
        ByteArray plainText = new ByteArray(vm, "r0ysue".getBytes(StandardCharsets.UTF_8));
        list.add(vm.addLocalObject(plainText));
        Number number = module.callFunction(emulator, 0x4a28D, list.toArray());
        return vm.getObject(number.intValue()).getValue().toString();
    };

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/izuiyou/common/base/BaseApplication->getAppContext()Landroid/content/Context;":
                return vm.resolveClass("android/content/Context").newObject(null);
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/content/Context->getClass()Ljava/lang/Class;":{
                return dvmObject.getObjectType();
            }
            case "java/lang/Class->getSimpleName()Ljava/lang/String;":{
                return new StringObject(vm, "AppController");
            }
            case "android/content/Context->getFilesDir()Ljava/io/File;":
            case "java/lang/String->getAbsolutePath()Ljava/lang/String;": {
                return new StringObject(vm, "/data/user/0/cn.xiaochuankeji.tieba/files");
            }
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    };

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature){
            case "android/os/Debug->isDebuggerConnected()Z":{
                return false;
            }
        }
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature){
            case "android/os/Process->myPid()I":{
                return emulator.getPid();
            }

        }
        throw new UnsupportedOperationException(signature);
    }

    public void hook65540(){
        // 加载HookZz
        IHookZz hookZz = HookZz.getInstance(emulator);

        hookZz.wrap(module.base + 0x65540 + 1, new WrapCallback<HookZzArm32RegisterContext>() { // inline wrap导出函数
            @Override
            // 类似于 frida onEnter
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                // 类似于Frida args[0]
                Inspector.inspect(ctx.getR0Pointer().getByteArray(0, 0x10), "Arg1");
                System.out.println(ctx.getR1Long());
                Inspector.inspect(ctx.getR2Pointer().getByteArray(0, 0x10), "Arg3");
                ctx.push(ctx.getR2Pointer());
            };

            @Override
            // 类似于 frida onLeave
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer output = ctx.pop();
                Inspector.inspect(output.getByteArray(0, 0x10), "Arg3 after function");
            }
        });
    }

    public void callMd5(){
        List<Object> list = new ArrayList<>(10);

        // arg1
        String input = "r0ysue";
        // malloc memory
        MemoryBlock memoryBlock1 = emulator.getMemory().malloc(16, false);
        // get memory pointer
        UnidbgPointer input_ptr=memoryBlock1.getPointer();
        // write plainText on it
        input_ptr.write(input.getBytes(StandardCharsets.UTF_8));

        // arg2
        int input_length = input.length();

        // arg3 -- buffer
        MemoryBlock memoryBlock2 = emulator.getMemory().malloc(16, false);
        UnidbgPointer output_buffer=memoryBlock2.getPointer();

        list.add(input_ptr);
        list.add(input_length);
        list.add(output_buffer);
        // run
        module.callFunction(emulator, 0x65540 + 1, list.toArray());

        // print arg3
        Inspector.inspect(output_buffer.getByteArray(0, 0x10), "output");
    };

    public void hook4E524(){
        hook(module.base + 0x4E524 + 1, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext context = emulator.getContext();
                final UnidbgPointer arg1 = context.getPointerArg(0);
                final UnidbgPointer arg2 = context.getPointerArg(1);
                final UnidbgPointer arg3 = context.getPointerArg(2);
                final UnidbgPointer arg4 = context.getPointerArg(3);
                Inspector.inspect("arg1:", arg1.toIntPeer());
                Inspector.inspect(arg1.getByteArray(0, 100), "arg1");
                Inspector.inspect("arg2:", arg2.toIntPeer());
                Inspector.inspect(arg2.getByteArray(0, 100), "arg2");
                Inspector.inspect("arg3:", arg3.toIntPeer());
                Inspector.inspect(arg3.getByteArray(0, 100), "arg3");
                Inspector.inspect("arg4:", arg4.toIntPeer());
                Inspector.inspect(arg4.getByteArray(0, 100), "arg4");
                return true;
            }
        });
    }

    public static void main(String[] args) throws Exception {
        zuiyou test = new zuiyou();
        test.native_init();
        //test.hook4E524();
//        test.callSign();
        test.hook65540();
//        System.out.println(test.callSign());
        test.callMd5();
    }
}
