package zju.cst.aces.dependencycheck.utils;


import edu.zju.cst.aces.sootex.ASMParser;
import edu.zju.cst.aces.sootex.CGType;
import edu.zju.cst.aces.sootex.SootExecutorUtil;
import edu.zju.cst.aces.sootex.callgraph.SimpleCallGraphFilter;
import javafx.util.Pair;
import org.apache.commons.io.FileUtils;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.MethodOrMethodContext;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.*;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
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
    public static HashMap<String, String> NPIJarsClassesDeterminer = new HashMap<>();


    public static HashMap<String, String> OWNJarsClassesDeterminer = new HashMap<>();

    public static HashMap<String, String> DIRECTJarsClassesDeterminer = new HashMap<>();

    public static HashMap<String, String> THIRDJarsClassesDeterminer = new HashMap<>();


    public static final Logger LOGGER = LoggerFactory.getLogger(FunctionUtil.class);


    public static Set<String> entrances = new HashSet<>();

    public static Set<Pair<String, String>> Intro_relations = new HashSet<>();

    public static final Logger NODE_LOGGER = LoggerFactory.getLogger("Node");
    public static final Logger EDGE_LOGGER = LoggerFactory.getLogger("Edge");

    private static File tmpFolder;

    private static CallGraph callGraph;


    //    public static final Logger RES_LOGGER = LoggerFactory.getLogger("RES");
    public static String functionDetect(String jarFile, String artifactid, boolean flag) {


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
            if (flag) targetClasses = candidateClasses;
            else {
                for (ClassNode node : candidateClasses
                ) {
                    //对于package name 按照artifactid进行命名的 ——准确

                    int i = 0;

                    if (!artifactid.contains(".jar")) {
                        for (String part : artifactidPart
                        ) {
                            if (node.name.replace("/", "").contains(part)) {
                                i++;
                            }
                        }

                        if (i == artifactidPart.length) {
                            targetClasses.add(node);
                            continue;
                        }
                    }
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

                    if (flag)
                        entrances.add(getMethodSignature(clazz.name, method.name, method.desc));


                }

            }
        } catch (IOException e) {
//            e.printStackTrace();
        }


        return Classmethodstr;

    }

    public static void findAllSig(String jarpath, String level) {
        try {

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
//        ClassReader classReader = new ClassReader("com/hundsun/jres/bizframe/cache/service/impl/BizLanguageCacheServiceImpl");

                    // 创建一个ClassVisitor对象，重写visit方法
                    ClassVisitor classVisitor = new ClassVisitor(Opcodes.ASM8) {
                        String classname = "";

                        @Override
                        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
                            // 打印类的全限定名
                            //调用父类的visit方法
                            classname = name.replace('/', '.');

                            super.visit(version, access, name, signature, superName, interfaces);
                        }

                        @Override
                        public MethodVisitor visitMethod(
                                final int access,
                                final String name,
                                final String descriptor,
                                final String signature,
                                final String[] exceptions) {

                            // 保存类的全限定名
                            switch (level) {
                                case "own":
                                    OWNJarsClassesDeterminer.put(classname, signature);
                                case "direct":
                                    DIRECTJarsClassesDeterminer.put(classname, signature);
                                case "third":
                                    THIRDJarsClassesDeterminer.put(classname, signature);
                                case "four":
                                    NPIJarsClassesDeterminer.put(classname, signature);
                            }

//                            System.out.println("The fully qualified method name is: " + name);
//                            System.out.println("The fully qualified method descriptor is: " + descriptor);


                            // 调用父类的visit方法
                            MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
                            return methodVisitor;
                        }

                        @Override
                        public FieldVisitor visitField(
                                final int access,
                                final String name,
                                final String descriptor,
                                final String signature,
                                final Object value) {
//                            System.out.println("The fully qualified field name is: " + name);
//                            System.out.println("The fully qualified field descriptor is: " + descriptor);
                            // 保存类的全限定名
                            switch (level) {
                                case "own":
                                    OWNJarsClassesDeterminer.put(classname, signature);
                                case "direct":
                                    DIRECTJarsClassesDeterminer.put(classname, signature);
                                case "third":
                                    THIRDJarsClassesDeterminer.put(classname, signature);
                                case "four":
                                    NPIJarsClassesDeterminer.put(classname, signature);
                            }

                            // 调用父类的visit方法
                            FieldVisitor fieldVisitor = super.visitField(access, name, descriptor, signature, value);
                            return fieldVisitor;

                        }
                    };
                    // 调用ClassReader的accept方法，传入ClassVisitor对象和读取模式
                    classReader.accept(classVisitor, 0);
                }
            }
        } catch (Exception e) {

        }
    }


    public static boolean findSourceMethod(SootMethod method, String npi_class_method, String npijar, boolean flag) {

        for (Iterator<Edge> it = callGraph.edgesInto(method); it.hasNext(); ) {
            //上一个src method 找到了
            if (flag) return flag;
            Edge edge = it.next();
            for (String ownjar : OWNJarsFunctions.keySet()) {

                String own_class_methodstr = OWNJarsFunctions.get(ownjar);
                String[] own_class_methods = own_class_methodstr.split(";");
                for (String own_class_method : own_class_methods) {

                    if (own_class_method.equals(edge.src().getDeclaringClass().getName() + "_" + edge.src().getName())) {
                        String clazz = own_class_method.split("_")[0];
                        String cla = npi_class_method.split("_")[0];
                        if (OWNJarsClassesDeterminer.get(clazz).contains(cla)) {
                            System.out.println("一方库Jar包: " + ownjar + " -> 孤立Jar包: " + npijar);
                            System.out.println("一方库Method: " + own_class_method + " -> Method: " + npi_class_method);

                            flag = true;
                            return flag;
                        }

                    }
                }

            }
            for (String directjar : DIRECTJarsFunctions.keySet()) {

                String direct_class_methodstr = DIRECTJarsFunctions.get(directjar);
                String[] direct_class_methods = direct_class_methodstr.split(";");
                for (String direct_class_method : direct_class_methods) {
                    if (direct_class_method.equals(edge.src().getDeclaringClass().getName() + "_" + edge.src().getName())) {
                        String clazz = direct_class_method.split("_")[0];
                        String cla = npi_class_method.split("_")[0];
                        if (DIRECTJarsClassesDeterminer.get(clazz).contains(cla)) {

                            System.out.println("二方库Jar包: " + directjar + " -> 孤立Jar包: " + npijar);
                            System.out.println("二方库Method: " + direct_class_method + " -> Method: " + npi_class_method);
                            flag = true;
                            return flag;
                        }
                    }
                }
            }
            for (String thirdjar : THIRDJarsFunctions.keySet()) {

                String third_class_methodstr = THIRDJarsFunctions.get(thirdjar);
                String[] third_class_methods = third_class_methodstr.split(";");
                for (String third_class_method : third_class_methods) {
                    if (third_class_method.equals(edge.src().getDeclaringClass().getName() + "_" + edge.src().getName())) {
                        String clazz = third_class_method.split("_")[0];
                        String cla = npi_class_method.split("_")[0];
                        if (THIRDJarsClassesDeterminer.get(clazz).contains(cla)) {

                            System.out.println("三方库Jar包: " + thirdjar + " -> 孤立Jar包: " + npijar);
                            System.out.println("三方库Method: " + third_class_method + " -> Method: " + npi_class_method);
                            flag = true;
                            return flag;
                        }
                    }
                }
            }


        }
        return flag;


    }

    public static String getMethodSignature(String className, String methodName, String methodDescriptor) {
        String returnType = Type.getReturnType(methodDescriptor).getClassName();
        List<String> argsType = Arrays.stream(Type.getArgumentTypes(methodDescriptor))
                .map(Type::getClassName)
                .collect(Collectors.toList());
        return String.format("<%s: %s %s(%s)>", className.replace("/", "."), returnType, methodName, String.join(",", argsType));
    }


    public static void CFGBuild() {


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

    }

    public static void findNPIIntro() {
        Set<String> findNPIJARs = new HashSet<>();

        for (Iterator<MethodOrMethodContext> iterator = Scene.v().getReachableMethods().listener(); iterator.hasNext(); ) {
            SootMethod method = (SootMethod) iterator.next();
            boolean flag = false;

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
                        if (!findNPIJARs.contains(npijar)) {
                            findNPIJARs.add(npijar);
                            System.out.println("第" + findNPIJARs.size() + "个孤立jar包: " + npijar);
                            System.out.println("孤立函数" + npi_class_method);
                        }


                        tag = findSourceMethod(method, npi_class_method, npijar, tag);


                        if (tag)
                            break;


                    }
                }
//                if (tag) break;
            }


        }

        for (String leftnpijar : NPIJarsFunctions.keySet()) {
            if (!findNPIJARs.contains(leftnpijar)) {
                System.out.println("没找到引入的孤立jar包: " + leftnpijar);
            }
        }
    }


}