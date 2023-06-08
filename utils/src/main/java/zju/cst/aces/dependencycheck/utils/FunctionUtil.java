package zju.cst.aces.dependencycheck.utils;


import edu.zju.cst.aces.sootex.ASMParser;
import edu.zju.cst.aces.sootex.CGType;
import edu.zju.cst.aces.sootex.RunConfig;
import edu.zju.cst.aces.sootex.SootExecutorUtil;
import edu.zju.cst.aces.sootex.callgraph.SimpleCallGraphFilter;
import javafx.util.Pair;
import org.apache.commons.io.FileUtils;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
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

public class FunctionUtil {


    /**
     * 这些默认方法不考虑
     */
    private static String DEFAULT_METHOD = "waitequalsnotifynotifyAlltoStringhashCodegetClass";


//    private static String PackageInclustr = "";
//    private  static String MethodInclustr = "";

    private static String Classmethodstr = "";
//    public static String className = "";

    //记录所有检测jar包的路径
    public static String ClassPaths = "";

    public static HashMap<String, String> NPIJarsFunctions = new HashMap<>();


    public static HashMap<String, String> OWNJarsFunctions = new HashMap<>();

    public static HashMap<String, String> DIRECTJarsFunctions = new HashMap<>();

    public static HashMap<String, String> THIRDJarsFunctions = new HashMap<>();


    public static final Logger LOGGER = LoggerFactory.getLogger(FunctionUtil.class);


    public static Set<String> entrances = new HashSet<>();

    public static Set<Pair<String, String>> Intro_relations = new HashSet<>();

    public static final Logger NODE_LOGGER = LoggerFactory.getLogger("Node");
    public static final Logger EDGE_LOGGER = LoggerFactory.getLogger("Edge");

    private static File tmpFolder;

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
                    // skip non-public methods and abstract method
                    if (method.access != Opcodes.ACC_PUBLIC)
                        continue;
                    Classmethodstr = Classmethodstr.concat(clazz.name + "_" + method.name).replace("/", ".") + ";";
                    //own direct jar
                    if (flag)
                        entrances.add(getMethodSignature(clazz.name, method.name, method.desc));

                }

            }
        } catch (IOException e) {
            e.printStackTrace();
        }


        return Classmethodstr;

    }

    public static void findSourceMethod(SootMethod method, CallGraph newCg, String npi_class_method, String npijar) {

        for (Iterator<Edge> it = newCg.edgesInto(method); it.hasNext(); ) {
            Edge edge = it.next();
//            LOGGER.info("All Methods {} Intruduce {}:",edge.src().getBytecodeSignature(),npi_class_method);

//            for (String ownjar : OWNJarsFunctions.keySet()) {
////                if(!Intro_relations.contains(new Pair<>(ownjar,npijar))){
////                    continue;
////                }
//                String own_class_methodstr = OWNJarsFunctions.get(ownjar);
//                String[] own_class_methods = own_class_methodstr.split(";");
//                for (String own_class_method : own_class_methods) {
//
//                    if (own_class_method.equals(edge.src().getDeclaringClass().getName() + "_" + edge.src().getName())) {
////                        if(!Intro_relations.contains(new Pair<>(ownjar,npijar))) {
////                            break;
////                        }
////                        if(!Intro_relations.contains(new Pair<>(ownjar,npijar)))
////                            Intro_relations.add(new Pair<>("一方库Jar包: "+ownjar,npijar));
//                        System.out.println("一方库Jar包: " + ownjar + " -> 孤立Jar包: " + npijar);
//                        System.out.println("一方库Method: " + own_class_method + " -> Method: " + npi_class_method);
//                        return;
////                        return;
//                    }
//                }
//
//            }
//            for (String directjar : DIRECTJarsFunctions.keySet()) {
////                if(!Intro_relations.contains(new Pair<>(directjar,npijar))){
////                    continue;
////                }
//                String direct_class_methodstr = DIRECTJarsFunctions.get(directjar);
//                String[] direct_class_methods = direct_class_methodstr.split(";");
//                for (String direct_class_method : direct_class_methods) {
//                    if (direct_class_method.equals(edge.src().getDeclaringClass().getName() + "_" + edge.src().getName())) {
////                        if(!Intro_relations.contains(new Pair<>(directjar,npijar))) {
////                            break;
////                        }
////                        Intro_relations.add(new Pair<>("二方库Jar包: "+directjar,npijar));
//
//                        System.out.println("二方库Jar包: " + directjar + " -> 孤立Jar包: " + npijar);
//                        System.out.println("二方库Method: " + direct_class_method + " -> Method: " + npi_class_method);
//                        return;
//                    }
//                }
//            }
            for (String thirdjar : THIRDJarsFunctions.keySet()) {
//                if(!Intro_relations.contains(new Pair<>(directjar,npijar))){
//                    continue;
//                }
                String third_class_methodstr = THIRDJarsFunctions.get(thirdjar);
                String[] third_class_methods = third_class_methodstr.split(";");
                for (String third_class_method : third_class_methods) {
                    if (third_class_method.equals(edge.src().getDeclaringClass().getName() + "_" + edge.src().getName())) {
//                        if(!Intro_relations.contains(new Pair<>(directjar,npijar))) {
//                            break;
//                        }
//                        Intro_relations.add(new Pair<>("二方库Jar包: "+directjar,npijar));

                        System.out.println("三方库Jar包: " + thirdjar + " -> 孤立Jar包: " + npijar);
                        System.out.println("三方库Method: " + third_class_method + " -> Method: " + npi_class_method);
                        return;
                    }
                }
            }

        }


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


//        默认先用CHA进行分析
        SootExecutorUtil.setSootEntryPoints(entrances);
//        SootExecutorUtil.doCHAAanalysis();

        SootExecutorUtil.doFastSparkPointsToAnalysis(new HashMap<>(), CGType.VTA, null);
        CallGraph cg = Scene.v().getCallGraph();


        LOGGER.info("Original size of CallGraph {}", cg.size());

        SimpleCallGraphFilter refiner = new SimpleCallGraphFilter();
        CallGraph newCg = refiner.refine(cg);
        Scene.v().setCallGraph(newCg);
        Scene.v().setReachableMethods(null);   //update reachable methods

        LOGGER.info("Start to dump call graph");
        Set<String> findNPIJARs = new HashSet<>();
        for (Iterator<MethodOrMethodContext> iterator = Scene.v().getReachableMethods().listener(); iterator.hasNext(); ) {
            SootMethod method = (SootMethod) iterator.next();

            NODE_LOGGER.info("{}: {} :{}", method.getBytecodeSignature(), method.getNumber(),method.getActiveBody());
            for (Iterator<Edge> it = newCg.edgesOutOf(method); it.hasNext(); ) {
                Edge edge = it.next();
                EDGE_LOGGER.info("{} -> {}", edge.src().getNumber(), edge.tgt().getNumber());
            }
//            NODE_LOGGER.info("{}: {}", method.getBytecodeSignature(), method.getNumber());
            boolean flag = false;


            //如果该method的下层引用全是jdk的method
            for (Iterator<Edge> it = newCg.edgesOutOf(method); it.hasNext(); ) {
                Edge edge = it.next();
                System.out.println();
                if (edge.tgt().getName() == method.getName()) {
                    flag = true;
                    break;
                }
            }
            if (flag)
                continue;
            ;

            //过滤简单函数
//            if(method.getName().equals("read")
//            ||method.getName().equals("equals")
//                    ||method.getName().equals("hash")
//                    ||method.getName().equals("write")
//                    ||method.getName().equals("call")
//                    ||method.getName().equals("get")
//                    ||method.getName().equals("add")
//                    ||method.getName().equals("put")
//                    ||method.getName().equals("next")
//                    ||method.getName().equals("hasNext")
//                    ||method.getName().equals("firstKey")
//                    ||method.getName().equals("size")
//                    ||method.getName().equals("hasnext")
//                    ||method.getName().equals("toString")
//                    ||method.getName().equals("<init>")
//                    ||method.getName().equals("bind")
//                    ||method.getName().equals("remove")
//                    ||method.getName().equals("toArray")
//                    ||method.getName().equals("indexOf")
//                    ||method.getName().equals("iterator")
//                    ||method.getName().equals("getValue")
//                    ||method.getName().equals("getKey")
//                    ||method.getName().equals("getKey")
//                    ||method.getName().equals("getKey")
//                    ||method.getName().equals("getKey")
//                    ||method.getName().equals("getKey")
//
//
//
//
//
//
//
//
//            )
//                continue;


//            System.out.println(method.getBytecodeSignature());
//            System.out.println("Methodtag:"+method.getDeclaringClass().getName()+"_"+method.getName());
//            LOGGER.info("{}_{}", method.getDeclaringClass().getName(), method.getName());


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

                        }

                        findSourceMethod(method, newCg, npi_class_method, npijar);


                    }
                }
            }


        }
//        for (Pair<String , String>:Intro_relations
//             ) {
//
//        }
        for (String leftnpijar : NPIJarsFunctions.keySet()) {
            if (!findNPIJARs.contains(leftnpijar)) {
                System.out.println("没找到引入的孤立jar包: " + leftnpijar);
            }
        }


    }



}
