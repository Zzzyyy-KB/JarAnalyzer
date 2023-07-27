package zju.cst.aces.dependencycheck.utils;

import edu.zju.cst.aces.sootex.ASMParser;
import edu.zju.cst.aces.sootex.CGType;
import edu.zju.cst.aces.sootex.SootExecutorUtil;
import edu.zju.cst.aces.sootex.callgraph.SimpleCallGraphFilter;
import javafx.util.Pair;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.MethodOrMethodContext;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.Map;


public class FunctionUtil {


    /**
     * 这些默认方法不考虑
     */
    private static String DEFAULT_METHOD = "waitequalsnotifynotifyAlltoStringhashCodegetClass";


//    private static String PackageInclustr = "";
//    private  static String MethodInclustr = "";

    private static String Classmethodstr = "";

    //记录所有检测jar包的路径
    public static String ClassPaths = "";

    public static HashMap<String, String> NPIJarsFunctions = new HashMap<>();


    public static HashMap<String, String> OWNJarsFunctions = new HashMap<>();

    public static HashMap<String, String> DIRECTJarsFunctions = new HashMap<>();

    public static HashMap<String, String> THIRDJarsFunctions = new HashMap<>();


    //记录每个level中一个class(key)的Determiner(value)


    public static HashMap<String, Set<String>> OWNJarsClassesDeterminer = new HashMap<>();

    public static HashMap<String, Set<String>> DIRECTJarsClassesDeterminer = new HashMap<>();

    public static HashMap<String, Set<String>> THIRDJarsClassesDeterminer = new HashMap<>();


    public static HashMap<String, String> OwnGroupDependenciesFilePaths = new HashMap<>();

    //
    public static HashMap<String, String> DirectGroupDependenciesFilePaths = new HashMap<>();

    public static HashMap<String, String> ThirdGroupDependenciesFilePaths = new HashMap<>();

    public static HashMap<String, List<String>> dep_vul = new HashMap<>();


    public static final Logger LOGGER = LoggerFactory.getLogger(FunctionUtil.class);


    public static Set<String> entrances = new HashSet<>();

    public static Set<Pair<String, String>> Intro_relations = new HashSet<>();

    public static final Logger EDGE_LOGGER = LoggerFactory.getLogger("Edge");

    private static File tmpFolder;

    private static CallGraph callGraph;

    public static HashMap<String, String> own = new HashMap<>();

    //    public static final Logger RES_LOGGER = LoggerFactory.getLogger("RES");
    public String functionDetect(String jarFile, String artifactid, String level) {


        //每个jar包包含的class_method重新赋值
        Classmethodstr = "";
        Set<ClassNode> candidateClasses = new HashSet<>();
        Set<ClassNode> targetClasses = new HashSet<>();

        try {
            // group id 过滤pom文件引入的class


            candidateClasses.addAll(ASMParser.loadClasses(new JarFile(jarFile)));
            String artifactidPart[] = artifactid.split("[-.]");

            //孤立jar包只找本项目编写的class
            //一二方库 入口是项目中的所有public函数
            if (level != "four") {
                targetClasses = candidateClasses;
            } else {
                for (ClassNode node : candidateClasses
                ) {
                    //对于package name 按照artifactid进行命名的 ——准确

//                    int i = 0;

//                    if (!artifactid.contains(".jar")) {
//                        for (String part : artifactidPart
//                        ) {
//                            if (node.name.replace("/", "").contains(part)) {
//                                i++;
//                            }
//                        }
//
//                        if (i == artifactidPart.length) {
//                            targetClasses.add(node);
//                            continue;
//                        }
//                    }
                    //对于不按照artifactid进行命名的 方便后续分类

                    String simnames[] = node.name.split("/");
                    for (String part : artifactidPart
                    ) {
                        int f = 0;
                        for (String simaname : simnames
                        ) {
                            if (simaname.contains(part) || part.contains(simaname)) {
                                targetClasses.add(node);
                                f = 1;
                                break;
                            }
                        }
                        if (f == 1) break;
                    }


                }
            }


            for (ClassNode clazz : targetClasses) {


                for (MethodNode method : clazz.methods) {
                    if (method.access != Opcodes.ACC_PUBLIC)
                        continue;
                    Classmethodstr = Classmethodstr.concat(clazz.name + "_" + method.name).replace("/", ".") + ";";

                    if (level != "four")
                        entrances.add(getMethodSignature(clazz.name, method.name, method.desc));


                }

            }
        } catch (IOException e) {
//            e.printStackTrace();
        }


        return Classmethodstr;

    }


    private static void findAllSig(String jarpath, String level) {
        try {
            boolean find = false;

            JarFile jarFile = new JarFile(jarpath);
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                // 获取当前条目
                JarEntry jarEntry = entries.nextElement();
                // 判断是否是一个class文件
                if (jarEntry.getName().endsWith(".class")) {

                    // 获取输入流
                    InputStream inputStream = jarFile.getInputStream(jarEntry);

                    ClassReader classReader = new ClassReader(inputStream);

                    // 创建一个ClassVisitor对象，重写visit方法
                    // 创建一个自定义的ClassVisitor
                    ClassVisitor classVisitor = new MyClassVisitor(level);
                    classReader.accept(classVisitor, 0);
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean findSourceMethod(SootMethod method, String npi_class_method, String npijar) {

        try {
            String npiclazz = npi_class_method.substring(0, npi_class_method.indexOf('_')).replace(".", "/");
//            SimpleDateFormat sdf = new SimpleDateFormat();// 格式化时间
//            sdf.applyPattern("yyyy-MM-dd HH:mm:ss a");// a为am/pm的标记
//            Date date = new Date();// 获取当前时间

            for (Iterator<Edge> it = callGraph.edgesInto(method); it.hasNext(); ) {
                //上一个src method 找到了
                Edge edge = it.next();
                SootMethod srcMethod = edge.src();
                SootClass srcClass = edge.src().getDeclaringClass();
                for (String ownjar : OWNJarsFunctions.keySet()) {
                    String own_class_methodstr = OWNJarsFunctions.get(ownjar);
                    String[] own_class_methods = own_class_methodstr.split(";");
                    for (String own_class_method : own_class_methods) {

                        if (own_class_method.equals(srcClass.getName() + "_" + srcMethod.getName())) {

                            if (OWNJarsClassesDeterminer == null
                                    || OWNJarsClassesDeterminer.get(srcClass.getName().replace(".", "/")) == null
                            ) {
                                String path = OwnGroupDependenciesFilePaths.get(ownjar);
                                findAllSig(path, "own");


                            }
                            //说明过滤jdk函数后没有
//                            if (OWNJarsClassesDeterminer == null
//                                    || OWNJarsClassesDeterminer.get(srcClass.getName().replace(".", "/")) == null)
//                                continue;

                            for (String signature : OWNJarsClassesDeterminer.get(srcClass.getName().replace(".", "/"))
                            ) {
                                if (signature == null) continue;

                                String[] parts = signature.split(";");


                                for (String part : parts
                                ) {
                                    if (part.replace("/", ".").contains(npiclazz)) {
                                        System.out.println("一方库Jar包: " + ownjar + " -> 孤立Jar包: " + npijar);
                                        System.out.println("一方库Method: " + own_class_method + " -> Method: " + npi_class_method);
                                        if (!findNPIJARs.contains(npijar)) {
                                            findNPIJARs.add(npijar);
                                            System.out.println("第" + findNPIJARs.size() + "个孤立jar包: " + npijar);
                                            System.out.println("孤立函数" + npi_class_method);
                                        }

                                        return true;
                                    }
                                }
                            }
//                            date = new Date();
//                            System.out.println("验证完一方时间：" + sdf.format(date));

                        }
                    }

                }
                for (String directjar : DIRECTJarsFunctions.keySet()) {

                    String direct_class_methodstr = DIRECTJarsFunctions.get(directjar);
                    String[] direct_class_methods = direct_class_methodstr.split(";");
                    for (String direct_class_method : direct_class_methods) {
                        if (direct_class_method.equals(srcClass.getName() + "_" + srcMethod.getName())) {
//                            date = new Date();
//                            System.out.println("找到二方包时间：" + sdf.format(date));
                            if (DIRECTJarsClassesDeterminer == null
                                    || DIRECTJarsClassesDeterminer.get(srcClass.getName().replace(".", "/")) == null
                            ) {
                                String path = DirectGroupDependenciesFilePaths.get(directjar);
                                findAllSig(path, "direct");
//                                date = new Date();
//                                System.out.println("找完二方sig包时间：" + sdf.format(date));
                            }
                            //说明过滤jdk函数后没有
//                            if (DIRECTJarsClassesDeterminer == null
//                                    || DIRECTJarsClassesDeterminer.get(srcClass.getName().replace(".", "/")) == null)
//                                continue;
//                            if (DIRECTJarsClassesDeterminer != null
//                                    && DIRECTJarsClassesDeterminer.get(srcClass.getName().replace(".", "/")) != null
//                            ) {
                            for (String signature : DIRECTJarsClassesDeterminer.get(srcClass.getName().replace(".", "/"))
                            ) {
                                if (signature == null) continue;

                                String[] parts = signature.split(";");

                                for (String part : parts
                                ) {
                                    if (part.replace("/", ".").contains(npiclazz)) {
                                        System.out.println("二方库Jar包: " + directjar + " -> 孤立Jar包: " + npijar);
                                        System.out.println("二方库Method: " + direct_class_method + " -> Method: " + npi_class_method);
                                        if (!findNPIJARs.contains(npijar)) {
                                            findNPIJARs.add(npijar);
                                            System.out.println("第" + findNPIJARs.size() + "个孤立jar包: " + npijar);
                                            System.out.println("孤立函数" + npi_class_method);
                                        }
                                        return true;
                                    }
                                }
                            }
//                            date = new Date();
//                            System.out.println("验证完二方包时间：" + sdf.format(date));

//                            }
                        }
                    }
                }
                for (String thirdjar : THIRDJarsFunctions.keySet()) {

                    if (thirdjar.equals(npijar)) continue;
                    String third_class_methodstr = THIRDJarsFunctions.get(thirdjar);
                    String[] third_class_methods = third_class_methodstr.split(";");
                    for (String third_class_method : third_class_methods) {
                        if (third_class_method.equals(srcClass.getName() + "_" + srcMethod.getName())) {
//                            date = new Date();
//                            System.out.println("找到三方包时间：" + sdf.format(date));
                            if (THIRDJarsClassesDeterminer == null
                                    || THIRDJarsClassesDeterminer.get(srcClass.getName().replace(".", "/")) == null
                            ) {
                                String path = ThirdGroupDependenciesFilePaths.get(thirdjar);
                                findAllSig(path, "third");
//                                date = new Date();
//                                System.out.println("找完三方sig时间：" + sdf.format(date));
                            }

                            //说明过滤jdk函数后没有
//                            if (THIRDJarsClassesDeterminer == null
//                                    || THIRDJarsClassesDeterminer.get(srcClass.getName().replace(".", "/")) == null)
//                                continue;
//                            if (THIRDJarsClassesDeterminer != null
//                                    && THIRDJarsClassesDeterminer.get(srcClass.getName().replace(".", "/")) != null
//                            ) {
                            for (String signature : THIRDJarsClassesDeterminer.get(srcClass.getName().replace(".", "/"))
                            ) {
                                if (signature == null) continue;
                                String[] parts = signature.split(";");

                                for (String part : parts
                                ) {
                                    if (part.contains(npiclazz)) {
                                        System.out.println("三方库Jar包: " + thirdjar + " -> 孤立Jar包: " + npijar);
                                        System.out.println("三方库Method: " + third_class_method + " -> Method: " + npi_class_method);
                                        if (!findNPIJARs.contains(npijar)) {
                                            findNPIJARs.add(npijar);
                                            System.out.println("第" + findNPIJARs.size() + "个孤立jar包: " + npijar);
                                            System.out.println("孤立函数" + npi_class_method);
                                        }
                                        return true;
                                    }
                                }


//                                }

                            }
//                            date = new Date();
//                            System.out.println("验证完三方包时间：" + sdf.format(date));
                        }
                    }

                }

            }
        } catch (NullPointerException e) {
//            e.printStackTrace();
        }

        return false;
    }

    private String getMethodSignature(String className, String methodName, String methodDescriptor) {
        String returnType = Type.getReturnType(methodDescriptor).getClassName();
        List<String> argsType = Arrays.stream(Type.getArgumentTypes(methodDescriptor))
                .map(Type::getClassName)
                .collect(Collectors.toList());
        return String.format("<%s: %s %s(%s)>", className.replace("/", "."), returnType, methodName, String.join(",", argsType));
    }


    public void CFGBuild() {


        SootExecutorUtil.setDefaultSootOptions(ClassPaths);


        SootExecutorUtil.setSootEntryPoints(entrances);

        try {
            SootExecutorUtil.doFastSparkPointsToAnalysis(new HashMap<>(), CGType.VTA, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
//        SootExecutorUtil.doCHAAanalysis();

//        System.out.println(j);
        CallGraph cg = Scene.v().getCallGraph();


        LOGGER.info("Original size of CallGraph {}", cg.size());

        SimpleCallGraphFilter refiner = new SimpleCallGraphFilter();
        CallGraph newCg = refiner.refine(cg);
        Scene.v().setCallGraph(newCg);
        callGraph = newCg;
        Scene.v().setReachableMethods(null);   //update reachable methods

        LOGGER.info("Start to dump call graph");
        //查找引入函数
//        findNPIIntro();
    }

    static Set<String> findNPIJARs = new HashSet<>();

    private void findNPIIntro() {
        for (Iterator<MethodOrMethodContext> iterator = Scene.v().getReachableMethods().listener(); iterator.hasNext(); ) {
            SootMethod method = (SootMethod) iterator.next();
            //过滤简单函数
            boolean tag = false;

            for (Map.Entry<String, String> it : NPIJarsFunctions.entrySet()) {
                String npijar = it.getKey();
                String npi_class_methodstr = it.getValue();
                if (npi_class_methodstr == "")
                    continue;
                String[] npi_class_methods = npi_class_methodstr.split(";");
                for (String npi_class_method : npi_class_methods) {
                    //当前NPIjar包中的函数在node中
                    if (npi_class_method.equals(method.getDeclaringClass().getName() + "_" + method.getName())) {
                        tag = findSourceMethod(method, npi_class_method, npijar);


                        if (tag)
                            break;


                    }
                }
                if (tag) break;
            }


        }

        for (String leftnpijar : NPIJarsFunctions.keySet()) {
            if (!findNPIJARs.contains(leftnpijar)) {
                System.out.println("没找到引入的孤立jar包: " + leftnpijar);
            }
        }
    }

    public static List<SootMethod> detectMethod = new ArrayList<>();

    private static boolean DFS(SootMethod method, boolean tag) {
        if (tag) return tag;
        for (Iterator<Edge> it = callGraph.edgesOutOf(method); it.hasNext(); ) {
            Edge edge = it.next();
            SootMethod tgtMethod = edge.tgt();
            if (detectMethod.contains(tgtMethod)) continue;
            detectMethod.add(tgtMethod);

            SootClass tgtClass = edge.tgt().getDeclaringClass();

            LOGGER.info(tgtMethod.getName() + " is called in " + tgtClass.getName());

            for (Map.Entry<String, List<String>> iterator : dep_vul.entrySet()) {
                String vul_dep = iterator.getKey();
                List<String> vul_funcs = iterator.getValue();
                for (String vul_func : vul_funcs) {
                    if (vul_func.replaceAll("/", ".").contains(tgtMethod.getName())) {
                        LOGGER.info(vul_func + " is founded in " + vul_dep);
                        if (vul_func.replaceAll("/", ".").contains(tgtClass.getName()))
                            LOGGER.info(vul_func + " in " + vul_dep + " is called");

                        tag = true;
                        return tag;
                    }
                }
            }
             tag = DFS(tgtMethod, tag);
            if(tag) return tag;
        }
        return false;

    }

    public static void vulFuncDetect(String detectJarName) {
        for (Iterator<MethodOrMethodContext> iterator = Scene.v().getReachableMethods().listener(); iterator.hasNext(); ) {
            SootMethod method = (SootMethod) iterator.next();
            //过滤简单函数
            boolean tag = false;
            String[] detectFuncs = OWNJarsFunctions.get(detectJarName).split(";");
            for (String detectfuc : detectFuncs
            ) {
                if (detectfuc.equals(method.getDeclaringClass().getName() + "_" + method.getName())) {
                    if (dep_vul != null)
                        DFS(method, false);
                }
            }


        }

    }


    static class MyClassVisitor extends ClassVisitor {
        String classname = "";
        private String level = "";

        public MyClassVisitor(String level) {
            super(Opcodes.ASM8);
            this.level = level;
        }


        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            // 打印类的全限定名
            //调用父类的visit方法
            classname = name;
            super.visit(version, access, name, signature, superName, interfaces);
        }

        @Override
        public MethodVisitor visitMethod(
                final int access,
                final String name,
                final String descriptor,
                final String signature,
                final String[] exceptions) {

            if (signature != null) {
                String[] parts = signature.split("[;<]");

                for (String part : parts
                ) {
                    if (part.contains("java")) continue;
                    if (part != null && part.contains("/")) {
                        switch (level) {
                            case "own":
                                if (OWNJarsClassesDeterminer.get(classname) == null) {
                                    OWNJarsClassesDeterminer.put(classname, new HashSet<>(Collections.singleton(part)));
                                } else OWNJarsClassesDeterminer.get(classname).add(part);
                            case "direct":
                                if (DIRECTJarsClassesDeterminer.get(classname) == null) {
                                    DIRECTJarsClassesDeterminer.put(classname, new HashSet<>(Collections.singleton(part)));
                                } else DIRECTJarsClassesDeterminer.get(classname).add(part);
                            case "third":
                                if (THIRDJarsClassesDeterminer.get(classname) == null) {
                                    THIRDJarsClassesDeterminer.put(classname, new HashSet<>(Collections.singleton(part)));
                                } else THIRDJarsClassesDeterminer.get(classname).add(part);
                        }
                    }
                }
                // 保存类的全限定名

            }


            // 调用父类的visit方法
            MethodVisitor mv = new MyMethodVisitor(level, classname);

            return mv;
        }

        @Override
        public FieldVisitor visitField(
                final int access,
                final String name,
                final String descriptor,
                final String signature,
                final Object value) {

            // 保存类的全限定名
            if (signature != null) {
                String[] parts = signature.split("[;<]");
                for (String part : parts
                ) {
                    if (part.contains("java")) continue;
                    if (part != null && part.contains("/")) {
                        switch (level) {
                            case "own":
                                if (OWNJarsClassesDeterminer.get(classname) == null) {
                                    OWNJarsClassesDeterminer.put(classname, new HashSet<>(Collections.singleton(part)));
                                } else OWNJarsClassesDeterminer.get(classname).add(part);
                            case "direct":
                                if (DIRECTJarsClassesDeterminer.get(classname) == null) {
                                    DIRECTJarsClassesDeterminer.put(classname, new HashSet<>(Collections.singleton(part)));
                                } else DIRECTJarsClassesDeterminer.get(classname).add(part);
                            case "third":
                                if (THIRDJarsClassesDeterminer.get(classname) == null) {
                                    THIRDJarsClassesDeterminer.put(classname, new HashSet<>(Collections.singleton(part)));
                                } else THIRDJarsClassesDeterminer.get(classname).add(part);
                        }
                    }
                }

            }
            // 调用父类的visit方法
            FieldVisitor fieldVisitor = super.visitField(access, name, descriptor, signature, value);
            return fieldVisitor;


        }
    }

    // 自定义的MethodVisitor，继承自ASM提供的MethodVisitor
    static class MyMethodVisitor extends MethodVisitor {
        String level = "";
        String classname = "";

        public MyMethodVisitor(String level, String classname) {
            super(Opcodes.ASM8);
            this.level = level;
            this.classname = classname;

        }

        // 重写visitLocalVariable方法，用于访问函数内部的局部变量
        @Override
        public void visitLocalVariable(
                final String name,
                final String descriptor,
                final String signature,
                final Label start,
                final Label end,
                final int index) {
            if (signature != null) {
                String[] parts = signature.split("[;<]");
                for (String part : parts
                ) {
                    if (part.contains("java")) continue;
                    if (part != null && part.contains("/")) {
                        switch (level) {
                            case "own":
                                if (OWNJarsClassesDeterminer.get(classname) == null) {
                                    OWNJarsClassesDeterminer.put(classname, new HashSet<>(Collections.singleton(part)));
                                } else OWNJarsClassesDeterminer.get(classname).add(part);
                            case "direct":
                                if (DIRECTJarsClassesDeterminer.get(classname) == null) {
                                    DIRECTJarsClassesDeterminer.put(classname, new HashSet<>(Collections.singleton(part)));
                                } else DIRECTJarsClassesDeterminer.get(classname).add(part);
                            case "third":
                                if (THIRDJarsClassesDeterminer.get(classname) == null) {
                                    THIRDJarsClassesDeterminer.put(classname, new HashSet<>(Collections.singleton(part)));
                                } else THIRDJarsClassesDeterminer.get(classname).add(part);
                        }
                    }
                }

            }
        }
    }

}

