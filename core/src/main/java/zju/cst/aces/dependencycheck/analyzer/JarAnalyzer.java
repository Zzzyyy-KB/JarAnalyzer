package zju.cst.aces.dependencycheck.analyzer;
/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */


import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import com.google.common.base.Strings;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.h2.util.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import zju.cst.aces.dependencycheck.Engine;
import zju.cst.aces.dependencycheck.analyzer.exception.AnalysisException;
import zju.cst.aces.dependencycheck.dependency.Confidence;
import zju.cst.aces.dependencycheck.dependency.Dependency;
import zju.cst.aces.dependencycheck.dependency.EvidenceType;
import zju.cst.aces.dependencycheck.dependency.naming.GenericIdentifier;
import zju.cst.aces.dependencycheck.dependency.naming.Identifier;
import zju.cst.aces.dependencycheck.dependency.naming.PurlIdentifier;
import zju.cst.aces.dependencycheck.exception.InitializationException;
import zju.cst.aces.dependencycheck.utils.*;
import zju.cst.aces.dependencycheck.xml.pom.Developer;
import zju.cst.aces.dependencycheck.xml.pom.License;
import zju.cst.aces.dependencycheck.xml.pom.Model;
import zju.cst.aces.dependencycheck.xml.pom.PomUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;


/**
 * Used to load a JAR file and collect information that can be used to determine
 * the associated CPE.
 *
 * @author Jeremy Long
 */
public class JarAnalyzer extends AbstractFileTypeAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="Constants and Member Variables">
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "java";

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(JarAnalyzer.class);
    /**
     * The count of directories created during analysis. This is used for
     * creating temporary directories.
     */
    private static final AtomicInteger DIR_COUNT = new AtomicInteger(0);
    /**
     * The system independent newline character.
     */
    private static final String NEWLINE = System.getProperty("line.separator");
    /**
     * A list of values in the manifest to ignore as they only result in false
     * positives.
     */
    private static final Set<String> IGNORE_VALUES = newHashSet(
            "Sun Java System Application Server");


    /**
     * A list of elements in the manifest to ignore.
     */
    private static final Set<String> IGNORE_KEYS = newHashSet(
            "built-by",
            "created-by",
            "builtby",
            "built-with",
            "builtwith",
            "createdby",
            "build-jdk",
            "buildjdk",
            "ant-version",
            "antversion",
            "dynamicimportpackage",
            "dynamicimport-package",
            "dynamic-importpackage",
            "dynamic-import-package",
            "import-package",
            "ignore-package",
            "export-package",
            "importpackage",
            "import-template",
            "importtemplate",
            "java-vendor",
            "export-template",
            "exporttemplate",
            "ignorepackage",
            "exportpackage",
            "sealed",
            "manifest-version",
            "archiver-version",
            "manifestversion",
            "archiverversion",
            "classpath",
            "class-path",
            "tool",
            "bundle-manifestversion",
            "bundlemanifestversion",
            "bundle-vendor",
            "include-resource",
            "embed-dependency",
            "embedded-artifacts",
            "ipojo-components",
            "ipojo-extension",
            "plugin-dependencies",
            "today",
            "tstamp",
            "dstamp",
            "eclipse-sourcereferences",
            "kotlin-version");
    /**
     * Deprecated Jar manifest attribute, that is, nonetheless, useful for
     * analysis.
     */
    @SuppressWarnings("deprecation")
    private static final String IMPLEMENTATION_VENDOR_ID = Attributes.Name.IMPLEMENTATION_VENDOR_ID
            .toString();
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_VERSION = "Bundle-Version"; //: 2.1.2
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_DESCRIPTION = "Bundle-Description"; //: Apache Struts 2
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_NAME = "Bundle-Name"; //: Struts 2 Core
    /**
     * A pattern to detect HTML within text.
     */
    private static final Pattern HTML_DETECTION_PATTERN = Pattern.compile("\\<[a-z]+.*/?\\>", Pattern.CASE_INSENSITIVE);
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Jar Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The set of jar files to exclude from analysis.
     */
    private static final List<String> EXCLUDE_JARS = Arrays.asList("-doc.jar", "-src.jar", "-javadoc.jar", "-sources.jar");
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final String[] EXTENSIONS = {"jar", "war", "aar"};
    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(EXTENSIONS).build();

    /**
     * The expected first bytes when reading a zip file.
     */
    private static final byte[] ZIP_FIRST_BYTES = new byte[]{0x50, 0x4B, 0x03, 0x04};

    /**
     * The expected first bytes when reading an empty zip file.
     */
    private static final byte[] ZIP_EMPTY_FIRST_BYTES = new byte[]{0x50, 0x4B, 0x05, 0x06};

    /**
     * The expected first bytes when reading a spanned zip file.
     */
    private static final byte[] ZIP_SPANNED_FIRST_BYTES = new byte[]{0x50, 0x4B, 0x07, 0x08};

    //</editor-fold>
    /**
     * The parent directory for the individual directories per archive.
     */
    public static File tempFileLocation = null;
    /**
     * Maven group id and artifact ids must match the regex to be considered
     * valid. In some cases ODC cannot interpolate a variable and it produced
     * invalid names.
     */
    private static final String VALID_NAME = "^[A-Za-z0-9_\\-.]+$";

    private String ownname = "";
    private String directname = "";

    //构建dependency tree所需变量
    static int[] degree = new int[1000];


    //数组长度需要改变
    public static int[][] adj = new int[500][500];

    //找到引入边的无pom包

    public static HashMap<Dependency, Integer> findIntroNoPomJars = new HashMap<>();

    HashMap<String, ArrayList<String>> isistEdges = new HashMap<>();
    public static HashMap<String, String> GroupBehalfNode = new HashMap<>();

    public static HashMap<String, String> name_Group = new HashMap<>();

    public static HashMap<String, Dependency> name_dependency = new HashMap<>();


    public static HashMap<Integer, Dependency> OwnGroupDependencies = new HashMap<>();

    //
    public static HashMap<Integer, Dependency> DirectGroupDependencies = new HashMap<>();

    public static HashMap<Integer, Dependency> ThirdGroupDependencies = new HashMap<>();

    public static HashMap<Dependency, Dependency> NoPomJarIntroFromPom = new HashMap<>();

    public static HashMap<Integer, Dependency> NPIJars = new HashMap<>();


    //<editor-fold defaultstate="collapsed" desc="All standard implmentation details of Analyzer">

    /**
     * Returns the FileFilter.
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    @Override
    public boolean accept(File pathname) {
        final boolean accepted = super.accept(pathname);
        return accepted && !isExcludedJar(pathname);
    }

    /**
     * Returns true if the JAR is a `*-sources.jar` or `*-javadoc.jar`;
     * otherwise false.
     *
     * @param path the path to the dependency
     * @return true if the JAR is a `*-sources.jar` or `*-javadoc.jar`;
     * otherwise false.
     */
    private boolean isExcludedJar(File path) {
        final String fileName = path.getName().toLowerCase();
        return EXCLUDE_JARS.stream().anyMatch(fileName::endsWith);
    }
    //</editor-fold>


    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_JAR_ENABLED;
    }

    /**
     * Loads a specified JAR file and collects information from the manifest and
     * checksums to identify the correct CPE information.
     *
     * @param dependency the dependency to analyze.
     * @param engine     the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     *                           file.
     */
    @Override
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final List<ClassNameInformation> classNames = collectClassNames(dependency);
        final String fileName = dependency.getFileName().toLowerCase();

        //把待检测依赖加入依赖集
//        if ((classNames.isEmpty()
//                && (fileName.endsWith("-sources.jar")
//                || fileName.endsWith("-javadoc.jar")
//                || fileName.endsWith("-src.jar")
//                || fileName.endsWith("-doc.jar")
//                || isMacOSMetaDataFile(dependency, engine)))
//                || !isZipFile(dependency)) {
//            engine.removeDependency(dependency);
//            return;
//        }
        Exception exception = null;
        boolean hasManifest = false;
        try {
            hasManifest = parseManifest(dependency, classNames);
        } catch (IOException ex) {
            LOGGER.debug("Invalid Manifest", ex);
            exception = ex;
        }
        boolean hasPOM = false;
        try {
            hasPOM = analyzePOM(dependency, classNames, engine);
        } catch (AnalysisException ex) {
            LOGGER.debug("Error parsing pom.xml", ex);
            exception = ex;
        }


        final boolean addPackagesAsEvidence = !(hasManifest && hasPOM);
        analyzePackageNames(classNames, dependency, addPackagesAsEvidence);
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);

        if (exception != null) {
            throw new AnalysisException(String.format("An error occurred extracting evidence from "
                            + "%s, analysis may be incomplete; please see the log for more details.",
                    dependency.getDisplayFileName()), exception);
        }


    }

    /**
     * Checks if the given dependency appears to be a macOS meta-data file,
     * returning true if its filename starts with a ._ prefix and if there is
     * another dependency with the same filename minus the ._ prefix, otherwise
     * it returns false.
     *
     * @param dependency the dependency to check if it's a macOS meta-data file
     * @param engine     the engine that is scanning the dependencies
     * @return whether or not the given dependency appears to be a macOS
     * meta-data file
     */
    @SuppressFBWarnings(justification = "If actual file path is not null the path will have elements and getFileName will not be called on a null",
            value = {"NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE"})
    private boolean isMacOSMetaDataFile(final Dependency dependency, final Engine engine) {
        if (dependency.getActualFilePath() != null) {
            final String fileName = Paths.get(dependency.getActualFilePath()).getFileName().toString();
            return fileName.startsWith("._") && hasDependencyWithFilename(engine.getDependencies(), fileName.substring(2));
        }
        return false;
    }

    /**
     * Iterates through the given list of dependencies and returns true when it
     * finds a dependency with a filename matching the given filename, otherwise
     * returns false.
     *
     * @param dependencies the dependencies to search within
     * @param fileName     the filename to search for
     * @return whether or not the given dependencies contain a dependency with
     * the given filename
     */
    @SuppressFBWarnings(justification = "If actual file path is not null the path will have elements and getFileName will not be called on a null",
            value = {"NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE"})
    private boolean hasDependencyWithFilename(final Dependency[] dependencies, final String fileName) {
        for (final Dependency dependency : dependencies) {
            if (dependency.getActualFilePath() != null
                    && Paths.get(dependency.getActualFilePath()).getFileName().toString().equalsIgnoreCase(fileName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Attempts to read the first bytes of the given dependency (using its
     * actual file path) and returns true if they match the expected first bytes
     * of a zip file, which may be empty or spanned. If they don't match, or if
     * the file could not be read, then it returns false.
     *
     * @param dependency the dependency to check if it's a zip file
     * @return whether or not the given dependency appears to be a zip file from
     * its first bytes
     */
    @SuppressFBWarnings(justification = "try with resources will clean up the output stream", value = {"OBL_UNSATISFIED_OBLIGATION"})
    private boolean isZipFile(final Dependency dependency) {
        final byte[] buffer = new byte[4];
        try (FileInputStream fileInputStream = new FileInputStream(dependency.getActualFilePath())) {
            if (fileInputStream.read(buffer) > 0
                    && (Arrays.equals(buffer, ZIP_FIRST_BYTES)
                    || Arrays.equals(buffer, ZIP_EMPTY_FIRST_BYTES)
                    || Arrays.equals(buffer, ZIP_SPANNED_FIRST_BYTES))) {
                return true;
            }
        } catch (Exception e) {
            LOGGER.warn("Unable to check if '{}' is a zip file", dependency.getActualFilePath());
            LOGGER.trace("", e);
        }
        return false;
    }

    public void analyzeIntro(Dependency dependency, List<Dependency> dcDependencies, int index, String MARKFILE) throws XmlPullParserException {
        if (index == 0) {
            try {
                File file = new File(MARKFILE);
                String content = org.apache.commons.io.FileUtils.readFileToString(file, "UTF-8");
                JSONObject jsonObject = new JSONObject(content);
                ownname = jsonObject.getString("一方库名");
                directname = jsonObject.getString("二方库前缀");
            } catch (JSONException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        //对shaded jar包操作
        if (dependency.getDisplayFileName().contains("shaded")) {
            //影响版本的jar包
            String influenceJarName = dependency.getDisplayFileName().substring(0, org.apache.commons.lang.StringUtils.ordinalIndexOf(dependency.getDisplayFileName(), "(", 1) - 1);


            dependency.Groupname = name_Group.get(influenceJarName);
            if (dependency.artifactid == null) {
                dependency.artifactid = dependency.getDisplayFileName();
//                System.out.println(dependency.getDisplayFileName());
            }
            dependency.level = name_dependency.get(influenceJarName).level;

        }

        try (JarFile jar = new JarFile(dependency.getActualFilePath(), false)) {

            final List<String> pomEntries = retrievePomListing(jar);


            if (pomEntries.size() == 0)
                return;


            for (String path : pomEntries) {

                LOGGER.debug("Reading pom entry: {}", path);
                try {
                    //extract POM to its own directory and add it as its own dependency
                    final Properties pomProperties = retrievePomProperties(path, jar);

                    final File pomFile = extractPom(path, jar);

                    final Model pom = PomUtils.readPom(pomFile);
                    pom.processProperties(pomProperties);

                    String groupid = pom.getGroupId();
                    if (groupid == null || groupid.equals("${project.parent.groupId}"))
                        groupid = pom.getParentGroupId();

                    if (dependency.artifactid == null) {
                        dependency.artifactid = pom.getArtifactId();
                        dependency.Groupname = groupid;

                    }
                    //分组

                    name_Group.put(dependency.getFileName(), groupid);
                    name_dependency.put(dependency.getFileName(), dependency);
                    String artifactid = pom.getArtifactId();

//                    FunctionUtil.ClassPaths = FunctionUtil.ClassPaths.concat(File.pathSeparatorChar+dependency.getActualFilePath());
                    //用第一个pom文件的artifactid 就是本项目的artifactid（启发式）


                    if (GroupBehalfNode.get(groupid) == null)
                        GroupBehalfNode.put(groupid, dependency.getDisplayFileName());

                    //读取一方库、二方库


                    //判断一方、二方、三方包
                    if (dependency.Groupname.equals(ownname)) {
                        dependency.level = "own";
                        OwnGroupDependencies.put(OwnGroupDependencies.size(), dependency);
                    }
                    //第二个.的子串 eg com.hundson.jrecloud
//                else if(dependency.Groupname.contains((dcDependencies.get(0).Groupname.substring(0,org.apache.commons.lang.StringUtils.ordinalIndexOf(dcDependencies.get(0).Groupname,".",2))))){
                    else if (dependency.Groupname.contains(directname)) {
                        dependency.level = "direct";
                        DirectGroupDependencies.put(DirectGroupDependencies.size(), dependency);
                    } else {
                        dependency.level = "third";
                        ThirdGroupDependencies.put(ThirdGroupDependencies.size(), dependency);

                    }


                    //找边

                    //找出G:A:V

                    MavenXpp3Reader reader = new MavenXpp3Reader();

                    FileInputStream fis = new FileInputStream(pomFile);
                    org.apache.maven.model.Model model = reader.read(fis);
                    List<org.apache.maven.model.Dependency> dependencies = model.getDependencies();


                    if (!(dependencies.toString() == "[]")) {
                        String[] array1 = dependencies.toString().split("Dependency");
                        String artifactIdtemp = "", groupIdtemp = "", versiontemp = "";
                        for (int i = 1; i < array1.length; i++) {
                            String str = array1[i];


                            if (str.contains("artifactId=")) {
                                artifactIdtemp = str.substring(str.indexOf("artifactId=") + 11, org.apache.commons.lang.StringUtils.ordinalIndexOf(str, ",", 2));

                                if (artifactIdtemp == null)
                                    continue;


                                if (str.contains("groupId=")) {
                                    groupIdtemp = str.substring(str.indexOf("groupId=") + 8, org.apache.commons.lang.StringUtils.ordinalIndexOf(str, ",", 1));
                                }

                                if (groupIdtemp.equals("${project.groupId}")) {
                                    if (pom.getGroupId() == null)
                                        groupIdtemp = pom.getParentGroupId();
                                    else groupIdtemp = pom.getGroupId();
                                }

                                if (str.contains("version=")) {
                                    versiontemp = str.substring(str.indexOf("version=") + 8, org.apache.commons.lang.StringUtils.ordinalIndexOf(str, ",", 3));
                                    if (versiontemp.equals("${project.version}")) {
                                        if (model.getVersion() == null)
                                            versiontemp = model.getParent().getVersion();
                                        else versiontemp = model.getVersion();

                                    } else if (versiontemp.equals("${project.parent.version}"))
                                        versiontemp = model.getParent().getVersion();

                                }
                                detectIntro(dcDependencies, index, groupIdtemp, artifactIdtemp, true);


                            }


                        }


                    }


                } catch (ZipException e) {
                    throw new RuntimeException(e);
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                } catch (AnalysisException e) {
                    throw new RuntimeException(e);

                }

            }


        } catch (IOException ex) {
//            LOGGER.warn("Unable to read JarFile '{}'.", dependency.getActualFilePath());
//            LOGGER.trace("", ex);
        }

    }


    public void detectIntro(List<Dependency> dcDependencies, int index, String groupIdtemp, String artifactIdtemp, boolean flag) {
        String d_name = groupIdtemp + ":" + artifactIdtemp;
        if (artifactIdtemp.contains("${"))
            return;
        //标记pom引入边
        int k = 0;
        for (Dependency dep : dcDependencies
        ) {

            if (dep.getName() != null && dep.getName().equals(d_name)) {
                adj[index][k] = 1;
                degree[k]++;
            }


            /*
             *
             *有pom文件的也需要用名字匹配artifactid判断
             *collection4  不考虑版本号了
             * 如果前面有也是作为开头，如果没有前面，则artifactIdtemp应作为头
             * but: spring-boot-starter-json-2.2.2.RELEASE.jar
             * */

            else if (dep.getFileName() != null && dep.getFileName().matches("(\\S.)*" + artifactIdtemp + "-?\\d.*")) {

//                                            System.out.println(dependency.getDisplayFileName()+"-----》"+dep.getDisplayFileName());

                if (dep.level == "four") {
                    dep.Groupname = groupIdtemp;
                    dep.artifactid = artifactIdtemp;
                    findIntroNoPomJars.put(dep, k);
                    searchPomAndDetectIntro(dep, dcDependencies);
                }
                adj[index][k] = 1;
                degree[k]++;

            } else if (dep.getFileName() != null && dep.getFileName().contains("-j-")) {
                if (dep.getFileName().replace("-j-", "-java").matches("(\\S.)*" + artifactIdtemp + "-?\\d.*")) {
                    if (dep.level == "four") {
                        dep.Groupname = groupIdtemp;
                        dep.artifactid = artifactIdtemp;
                        findIntroNoPomJars.put(dep, k);
                        searchPomAndDetectIntro(dep, dcDependencies);
                    }
                    adj[index][k] = 1;
                    degree[k]++;
                }
            }

            k++;
        }
    }

    public void searchPomAndDetectIntro(Dependency dependency, List<Dependency> dcDependencies) {
        try {
            dependency.level = "four-third";

            String level = dependency.getFileName().substring(dependency.getFileName().lastIndexOf("-") + 1, dependency.getDisplayFileName().lastIndexOf(".jar"));
            int index = findIntroNoPomJars.get(dependency);
            String pomName = dependency.getFileName().replace("jar", "pom");
            Crawler crawler = new Crawler("https://repo1.maven.org/maven2/" + dependency.Groupname.replace(".", "/") + "/" + dependency.artifactid + "/" + level + "/" + pomName);
            ArrayList<String> dependecies = crawler.Crawl();
            if (dependecies == null) {
                System.out.println("还是没有的：" + dependency.getFileName());
                return;
            }
            for (String d_name : dependecies) {
                String[] Array = d_name.split(":");
                detectIntro(dcDependencies, index, Array[0], Array[1], false);
            }
        } catch (Exception e) {

        }

    }


    public void detectNPIJar(List<Dependency> dcDependencies) {

        for (int i = 0; i < dcDependencies.size(); i++) {
            FunctionUtil.ClassPaths = FunctionUtil.ClassPaths.concat(dcDependencies.get(i).getActualFilePath().replace('\\', '/') + File.pathSeparatorChar);

            //排除一方、二方库以及war包后的 非pom引入jar包
            if (dcDependencies.get(i).level != "own" && dcDependencies.get(i).level != "direct") {
                if (degree[i] == 0) {
                    Dependency dependency = dcDependencies.get(i);
                    if (!dependency.getDisplayFileName().contains("shaded")) {
                        NPIJars.put(NPIJars.size(), dependency);
                        System.out.println("NPI JAR:" + dependency.getDisplayFileName());
                    }
                }
            }
        }

//        //找到一方、二方库jar的所有public函数
        for (Dependency owndependency : OwnGroupDependencies.values()) {
            String classfunctionstr = FunctionUtil.functionDetect(owndependency.getActualFilePath().replace('\\', '/'), owndependency.artifactid, true);
            FunctionUtil.findAllSig(owndependency.getActualFilePath().replace('\\', '/'),"own");

            if (classfunctionstr != "")
                FunctionUtil.OWNJarsFunctions.put(owndependency.getDisplayFileName(), classfunctionstr);
        }
        for (Dependency directdependency : DirectGroupDependencies.values()) {
            String classfunctionstr = FunctionUtil.functionDetect(directdependency.getActualFilePath().replace('\\', '/'), directdependency.artifactid, true);
            FunctionUtil.findAllSig(directdependency.getActualFilePath().replace('\\', '/'),"direct");
            if (classfunctionstr != "")
                FunctionUtil.DIRECTJarsFunctions.put(directdependency.getDisplayFileName(), classfunctionstr);
        }

        for (Dependency thirddependency : ThirdGroupDependencies.values()) {
            int flag = 0;
            for (Dependency npijar : NPIJars.values()
            ) {
                if (thirddependency == npijar) {
                    flag = 1;
                    break;
                }
            }
            if (flag == 1) continue;
            FunctionUtil.findAllSig(thirddependency.getActualFilePath().replace('\\', '/'),"third");

            String classfunctionstr = FunctionUtil.functionDetect(thirddependency.getActualFilePath().replace('\\', '/'), thirddependency.artifactid, true);
            if (classfunctionstr != "")
                FunctionUtil.THIRDJarsFunctions.put(thirddependency.getDisplayFileName(), classfunctionstr);
        }

        for (Dependency NPIJar : NPIJars.values()) {
            String classfunctionstr = FunctionUtil.functionDetect(NPIJar.getActualFilePath().replace('\\', '/'), NPIJar.artifactid, false);
//            FunctionUtil.findAllSig(NPIJar.getActualFilePath().replace('\\', '/'),"four;");
            if (classfunctionstr != "") {
                FunctionUtil.NPIJarsFunctions.put(NPIJar.getDisplayFileName(), classfunctionstr);
            } else System.out.println("classfunctionstr为空的孤立Jar包: " + NPIJar.getDisplayFileName());
        }


        FunctionUtil.CFGBuild();
//        //获取NPIjar的所有函数名int i =0;

        FunctionUtil.findNPIIntro();



    }

    public File creatSJsonFile(String path) {
        try {
            File file = new File(path);


            if (!file.getParentFile().exists()) { // 如果父目录不存在，创建父目录
                file.getParentFile().mkdirs();
            }
            if (file.exists()) { // 如果已存在,删除旧文件
                file.delete();
            }
            file.createNewFile();
            return file;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }

    public void writeJsonFile(File file, JSONObject root) {
        try {
            String jsonString1 = formatJson(root.toString());
            // 将格式化后的字符串写入文件
            Writer write1 = new OutputStreamWriter(new FileOutputStream(file), "UTF-8");
            write1.write(jsonString1);
            write1.flush();
            write1.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void buildDependencyTree(List<Dependency> dependencies) {


//
        JarAnalyzer jarAnalyzer = new JarAnalyzer();
//
        JSONObject root1 = new JSONObject();

        JSONObject root4 = new JSONObject();

        JSONArray nodes = new JSONArray();


        String nodePath = "./node.json";
        String nodEedgePath = "./nodeedge.json";


        try {
            File file1 = creatSJsonFile(nodePath);
            File file4 = creatSJsonFile(nodEedgePath);
//
//
//
//
//
            for (Dependency dependency : dependencies
            ) {

                JSONObject node = new JSONObject();

                node.put("id", dependency.getDisplayFileName());
                node.put("level", dependency.level);
                node.put("label", dependency.getDisplayFileName());
                nodes.put(node);


            }

            JSONArray nodeEdges = new JSONArray();

            for (int i = 0; i < dependencies.size(); i++) {
                jarAnalyzer.addEdges(i, nodeEdges, dependencies);
            }
            root4.put("nodeEdges", nodeEdges);
            writeJsonFile(file4, root4);

            root1.put("nodes", nodes);
            writeJsonFile(file1, root1);


            //加边
//            jarAnalyzer.topoSort(edges,nodeEdges,dependencies);


        } catch (Exception e) {
            e.printStackTrace();
        }


    }


    /**
     * Attempts to find a pom.xml within the JAR file. If found it extracts
     * information and adds it to the evidence. This will attempt to interpolate
     * the strings contained within the pom.properties if one exists.
     *
     * @param dependency the dependency being analyzed
     * @param classes    a collection of class name information
     * @param engine     the analysis engine, used to add additional dependencies
     * @return whether or not evidence was added to the dependency
     * @throws AnalysisException is thrown if there is an exception parsing the
     *                           pom
     */

    protected boolean analyzePOM(Dependency dependency, List<ClassNameInformation> classes, Engine engine) throws AnalysisException {


        //TODO add breakpoint on groov-all to find out why commons-cli is not added as a new dependency?
        boolean evidenceAdded = false;

        try (JarFile jar = new JarFile(dependency.getActualFilePath(), false)) {
            //check if we are scanning in a repo directory - so the pom is adjacent to the jar
            final String repoPomName = FilenameUtils.removeExtension(dependency.getActualFilePath()) + ".pom";
            final File repoPom = new File(repoPomName);
            if (repoPom.isFile()) {
                final Model pom = PomUtils.readPom(repoPom);
                evidenceAdded |= setPomEvidence(dependency, pom, classes, true);
            }

            final List<String> pomEntries = retrievePomListing(jar);


            //没有pom文件的
            if (pomEntries.size() == 0) {

//                GroupBehalfNode.put(dependency.getName(),dependency.getName());

                //没有pom文件的默认放在第四层
                dependency.Groupname = dependency.getFileName();
                dependency.artifactid = dependency.getFileName();
                dependency.level = "four";
                GroupBehalfNode.put(dependency.Groupname, dependency.getFileName());
                ThirdGroupDependencies.put(ThirdGroupDependencies.size(), dependency);
            }

            for (String path : pomEntries) {
                LOGGER.debug("Reading pom entry: {}", path);
                try {
                    //extract POM to its own directory and add it as its own dependency
                    final Properties pomProperties = retrievePomProperties(path, jar);
                    final File pomFile = extractPom(path, jar);
                    final Model pom = PomUtils.readPom(pomFile);
                    pom.processProperties(pomProperties);


                    final String artifactId = new File(path).getParentFile().getName();
                    if (dependency.getActualFile().getName().startsWith(artifactId)) {
                        evidenceAdded |= setPomEvidence(dependency, pom, classes, true);
                    } else {
                        final String displayPath = String.format("%s%s%s",
                                dependency.getFilePath(),
                                File.separator,
                                path);
                        final String displayName = String.format("%s%s%s",
                                dependency.getFileName(),
                                File.separator,
                                path);
                        final Dependency newDependency = new Dependency();
                        newDependency.setActualFilePath(pomFile.getAbsolutePath());
                        //保留原filename
//                        newDependency.setFileName(displayName);


                        newDependency.setFilePath(displayPath);
                        newDependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
                        String groupId = pom.getGroupId();
                        String version = pom.getVersion();

                        if (groupId == null || groupId.equals("${project.parent.groupId}"))
                            groupId = pom.getParentGroupId();

                        if (version == null) {
                            version = pom.getParentVersion();
                        }
                        if (groupId == null) {
                            newDependency.setName(pom.getArtifactId());
                            newDependency.setPackagePath(String.format("%s:%s", pom.getArtifactId(), version));
                        } else {

                            newDependency.setName(String.format("%s:%s", groupId, pom.getArtifactId()));
                            newDependency.setPackagePath(String.format("%s:%s:%s", groupId, pom.getArtifactId(), version));
                        }


                        newDependency.setDisplayFileName(String.format("%s (shaded: %s)", dependency.getDisplayFileName(), newDependency.getPackagePath()));
                        newDependency.setVersion(version);
                        setPomEvidence(newDependency, pom, null, true);
                        if (dependency.getProjectReferences().size() > 0) {
                            newDependency.addAllProjectReferences(dependency.getProjectReferences());
                        }
                        engine.addDependency(newDependency);
                    }
                } catch (AnalysisException ex) {
                    LOGGER.warn("An error occurred while analyzing '{}'.", dependency.getActualFilePath());
                    LOGGER.trace("", ex);
                }
            }
        } catch (IOException ex) {
            LOGGER.warn("Unable to read JarFile '{}'.", dependency.getActualFilePath());
            LOGGER.trace("", ex);
        }
        return evidenceAdded;
    }


    int[][] copyadj = adj;
    public Set<Integer> path = new HashSet<>();

    public void DFS(int index, JSONArray requestedby, List<Dependency> dependencies) {
        for (int i = 0; i < dependencies.size(); i++) {
            if (copyadj[i][index] == 1) {
                copyadj[i][index] = 0;
                if (!path.contains(i)) {
                    if (dependencies.get(i).level == "own" || dependencies.get(i).level == "direct")
                        requestedby.put(dependencies.get(i).Groupname + ":" + dependencies.get(i).getFileName());
                    path.add(i);
                }
                if (path.size() < 10)
                    DFS(i, requestedby, dependencies);
            }
        }
    }

    public void addEdges(int firstindex, JSONArray nodeEdges, List<Dependency> dependencies) throws JSONException {
        copyadj = adj;
        path = new HashSet<>();
        ArrayList<Integer> store = new ArrayList<>();
        JSONArray requestedby = new JSONArray();

        for (int i = 0; i < dependencies.size(); i++) {
            if (copyadj[i][firstindex] == 1) {
                Dependency nextdependency = dependencies.get(i);
                JSONObject nodeEdge = new JSONObject();

                nodeEdge.put("Jar Name", dependencies.get(firstindex).getDisplayFileName());

                JSONObject direct = new JSONObject();
                direct.put("Directly requested by:", nextdependency.Groupname + ":" + nextdependency.getDisplayFileName());

                requestedby.put(direct);
                copyadj[i][firstindex] = 0;
                path.add(firstindex);
                path.add(i);
                store.add(i);
                nodeEdge.put("Requested by", requestedby);
                nodeEdges.put(nodeEdge);
            }
        }
        for (int i = 0; i < store.size(); i++) {
            DFS(store.get(i), requestedby, dependencies);
        }

    }

    public void topoSort(JSONArray nodeEdges, List<Dependency> dependencies) {

        try {


            Queue<Integer> queue = new LinkedList<>();
            for (int i = 0; i < dependencies.size(); i++) {
                if (degree[i] == 0) {
                    queue.add(i);
                }
            }

            while (!queue.isEmpty()) {
                int firstindex = queue.poll();
                Dependency firstdependency = dependencies.get(firstindex);

                ArrayList<String> tempedge = new ArrayList<>();

                for (int i = 0; i < dependencies.size(); i++) {
                    if (adj[firstindex][i] == 1) {
                        Dependency nextdependency = dependencies.get(i);


//                        去除group内的边
                        String behalf1 = GroupBehalfNode.get(firstdependency.Groupname);

                        String behalf2 = GroupBehalfNode.get(nextdependency.Groupname);

                        if (behalf1 == null) behalf1 = firstdependency.getDisplayFileName();

                        if (behalf2 == null) behalf2 = nextdependency.getDisplayFileName();
                        if (!behalf1.equals(behalf2)) {

                            if (isistEdges.get(behalf1) == null || !isistEdges.get(behalf1).contains(behalf2)) {
                                if (isistEdges.get(behalf1) == null) {
                                    tempedge.add(behalf2);


                                    isistEdges.put(behalf1, tempedge);
                                } else {
                                    isistEdges.get(behalf1).add(behalf2);
                                }

                            }
                        }
                        JSONObject nodeEdge = new JSONObject();

                        nodeEdge.put("sourcenode", firstdependency.getDisplayFileName());
                        nodeEdge.put("source", firstdependency.Groupname);


                        nodeEdge.put("targetnode", nextdependency.getDisplayFileName());
                        nodeEdge.put("target", nextdependency.Groupname);
                        nodeEdge.put("mark", 0);

                        nodeEdges.put(nodeEdge);

                    }
                    degree[i]--;
                    if (degree[i] == 0) {
                        queue.add(i);
                    }
                }

            }


        } catch (JSONException e) {
            throw new RuntimeException(e);
        }


    }


    public static String formatJson(String json) {
        StringBuffer result = new StringBuffer();

        int length = json.length();
        int number = 0;
        char key = 0;

        // 遍历输入字符串。
        for (int i = 0; i < length; i++) {
            // 1、获取当前字符。
            key = json.charAt(i);

            // 2、如果当前字符是前方括号、前花括号做如下处理：
            if ((key == '[') || (key == '{')) {
                // （1）如果前面还有字符，并且字符为“：”，打印：换行和缩进字符字符串。
                if ((i - 1 > 0) && (json.charAt(i - 1) == ':')) {
                    result.append('\n');
                    result.append(indent(number));
                }

                // （2）打印：当前字符。
                result.append(key);

                // （3）前方括号、前花括号，的后面必须换行。打印：换行。
                result.append('\n');

                // （4）每出现一次前方括号、前花括号；缩进次数增加一次。打印：新行缩进。
                number++;
                result.append(indent(number));

                // （5）进行下一次循环。
                continue;
            }

            // 3、如果当前字符是后方括号、后花括号做如下处理：
            if ((key == ']') || (key == '}')) {
                // （1）后方括号、后花括号，的前面必须换行。打印：换行。
                result.append('\n');

                // （2）每出现一次后方括号、后花括号；缩进次数减少一次。打印：缩进。
                number--;
                result.append(indent(number));

                // （3）打印：当前字符。
                result.append(key);

                // （4）如果当前字符后面还有字符，并且字符不为“，”，打印：换行。
                if (((i + 1) < length) && (json.charAt(i + 1) != ',')) {
                    result.append('\n');
                }

                // （5）继续下一次循环。
                continue;
            }

            // 4、如果当前字符是逗号。逗号后面换行，并缩进，不改变缩进次数。
            if ((key == ',')) {
                result.append(key);
                result.append('\n');
                result.append(indent(number));
                continue;
            }

            // 5、打印：当前字符。
            result.append(key);
        }

        return result.toString();
    }


    private static String SPACE = "   ";

    /**
     * 返回指定次数的缩进字符串。每一次缩进三个空格，即SPACE。
     *
     * @param number 缩进次数。
     * @return 指定缩进次数的字符串。
     */
    private static String indent(int number) {
        StringBuffer result = new StringBuffer();
        for (int i = 0; i < number; i++) {
            result.append(SPACE);
        }
        return result.toString();
    }


    /**
     * Given a path to a pom.xml within a JarFile, this method attempts to load
     * a sibling pom.properties if one exists.
     *
     * @param path the path to the pom.xml within the JarFile
     * @param jar  the JarFile to load the pom.properties from
     * @return a Properties object or null if no pom.properties was found
     */
    private Properties retrievePomProperties(String path, final JarFile jar) {
        Properties pomProperties = null;
        final String propPath = path.substring(0, path.length() - 7) + "pom.properties";
        final ZipEntry propEntry = jar.getEntry(propPath);
        if (propEntry != null) {
            try (Reader reader = new InputStreamReader(jar.getInputStream(propEntry), StandardCharsets.UTF_8)) {
                pomProperties = new Properties();
                pomProperties.load(reader);
                LOGGER.debug("Read pom.properties: {}", propPath);
            } catch (UnsupportedEncodingException ex) {
                LOGGER.trace("UTF-8 is not supported", ex);
            } catch (IOException ex) {
                LOGGER.trace("Unable to read the POM properties", ex);
            }
        }
        return pomProperties;
    }

    /**
     * Searches a JarFile for pom.xml entries and returns a listing of these
     * entries.
     *
     * @param jar the JarFile to search
     * @return a list of pom.xml entries
     * @throws IOException thrown if there is an exception reading a JarEntry
     */
    private List<String> retrievePomListing(final JarFile jar) throws IOException {
        final List<String> pomEntries = new ArrayList<>();
        final Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            final JarEntry entry = entries.nextElement();
            final String entryName = new File(entry.getName()).getName().toLowerCase();
            if (!entry.isDirectory() && "pom.xml".equals(entryName)
                    && entry.getName().toUpperCase().startsWith("META-INF")) {
                pomEntries.add(entry.getName());
            }
        }
        return pomEntries;
    }

    /**
     * Retrieves the specified POM from a jar.
     *
     * @param path the path to the pom.xml file within the jar file
     * @param jar  the jar file to extract the pom from
     * @return returns the POM file
     * @throws AnalysisException is thrown if there is an exception extracting
     *                           the file
     */
    private File extractPom(String path, JarFile jar) throws AnalysisException {
        final File tmpDir = getNextTempDirectory();
        final File file = new File(tmpDir, "pom.xml");
        final ZipEntry entry = jar.getEntry(path);
        if (entry == null) {
            throw new AnalysisException(String.format("Pom (%s) does not exist in %s", path, jar.getName()));
        }
        try (InputStream input = jar.getInputStream(entry);
             FileOutputStream fos = new FileOutputStream(file)) {
            IOUtils.copy(input, fos);
        } catch (IOException ex) {
            LOGGER.warn("An error occurred reading '{}' from '{}'.", path, jar.getName());
            LOGGER.error("", ex);
        }
        return file;
    }

    /**
     * Sets evidence from the pom on the supplied dependency.
     *
     * @param dependency the dependency to set data on
     * @param pom        the information from the pom
     * @param classes    a collection of ClassNameInformation - containing data
     *                   about the fully qualified class names within the JAR file being analyzed
     * @param isMainPom  a flag indicating if this is the primary pom.
     * @return true if there was evidence within the pom that we could use;
     * otherwise false
     */
    public static boolean setPomEvidence(Dependency dependency, Model pom, List<ClassNameInformation> classes, boolean isMainPom) {
        if (pom == null) {
            return false;
        }
        boolean foundSomething = false;
        boolean addAsIdentifier = true;
        String groupid = pom.getGroupId();
        String parentGroupId = pom.getParentGroupId();
        String artifactid = pom.getArtifactId();
        String parentArtifactId = pom.getParentArtifactId();
        String version = pom.getVersion();
        String parentVersion = pom.getParentVersion();

        if (("org.sonatype.oss".equals(parentGroupId) && "oss-parent".equals(parentArtifactId))
                || ("org.springframework.boot".equals(parentGroupId) && "spring-boot-starter-parent".equals(parentArtifactId))) {
            parentGroupId = null;
            parentArtifactId = null;
            parentVersion = null;
        }

        if ((groupid == null || groupid.isEmpty()) && parentGroupId != null && !parentGroupId.isEmpty()) {
            groupid = parentGroupId;
        }

        final String originalGroupID = groupid;

        if ((artifactid == null || artifactid.isEmpty()) && parentArtifactId != null && !parentArtifactId.isEmpty()) {
            artifactid = parentArtifactId;
        }

        final String originalArtifactID = artifactid;
        if (artifactid != null && (artifactid.startsWith("org.") || artifactid.startsWith("com."))) {
            artifactid = artifactid.substring(4);
        }

        if ((version == null || version.isEmpty()) && parentVersion != null && !parentVersion.isEmpty()) {
            version = parentVersion;
        }

        if (isMainPom && dependency.getName() == null && originalArtifactID != null && !originalArtifactID.isEmpty()) {
            if (originalGroupID != null && !originalGroupID.isEmpty()) {
                dependency.setName(String.format("%s:%s", originalGroupID, originalArtifactID));
            } else {
                dependency.setName(originalArtifactID);
            }
        }
        if (isMainPom && dependency.getVersion() == null && version != null && !version.isEmpty()) {
            dependency.setVersion(version);
        }

        if (groupid != null && !groupid.isEmpty()) {
            foundSomething = true;
            dependency.addEvidence(EvidenceType.VENDOR, "pom", "groupid", groupid, Confidence.HIGHEST);
            //In several cases we are seeing the product name at the end of the group identifier.
            // This may cause several FP on products that have a collection of dependencies (e.g. jetty).
            //dependency.addEvidence(EvidenceType.PRODUCT, "pom", "groupid", groupid, Confidence.LOW);
            dependency.addEvidence(EvidenceType.PRODUCT, "pom", "groupid", groupid, Confidence.HIGHEST);
            addMatchingValues(classes, groupid, dependency, EvidenceType.VENDOR);
            addMatchingValues(classes, groupid, dependency, EvidenceType.PRODUCT);
            if (parentGroupId != null && !parentGroupId.isEmpty() && !parentGroupId.equals(groupid)) {
                dependency.addEvidence(EvidenceType.VENDOR, "pom", "parent-groupid", parentGroupId, Confidence.MEDIUM);
                //see note above for groupid
                //dependency.addEvidence(EvidenceType.PRODUCT, "pom", "parent-groupid", parentGroupId, Confidence.LOW);
                dependency.addEvidence(EvidenceType.PRODUCT, "pom", "parent-groupid", parentGroupId, Confidence.MEDIUM);
                addMatchingValues(classes, parentGroupId, dependency, EvidenceType.VENDOR);
                addMatchingValues(classes, parentGroupId, dependency, EvidenceType.PRODUCT);
            }
        } else {
            addAsIdentifier = false;
        }

        if (artifactid != null && !artifactid.isEmpty()) {
            foundSomething = true;
            dependency.addEvidence(EvidenceType.PRODUCT, "pom", "artifactid", artifactid, Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.VENDOR, "pom", "artifactid", artifactid, Confidence.LOW);
            addMatchingValues(classes, artifactid, dependency, EvidenceType.VENDOR);
            addMatchingValues(classes, artifactid, dependency, EvidenceType.PRODUCT);
            if (parentArtifactId != null && !parentArtifactId.isEmpty() && !parentArtifactId.equals(artifactid)) {
                dependency.addEvidence(EvidenceType.PRODUCT, "pom", "parent-artifactid", parentArtifactId, Confidence.MEDIUM);
                dependency.addEvidence(EvidenceType.VENDOR, "pom", "parent-artifactid", parentArtifactId, Confidence.LOW);
                addMatchingValues(classes, parentArtifactId, dependency, EvidenceType.VENDOR);
                addMatchingValues(classes, parentArtifactId, dependency, EvidenceType.PRODUCT);
            }
        } else {
            addAsIdentifier = false;
        }

        if (version != null && !version.isEmpty()) {
            foundSomething = true;
            dependency.addEvidence(EvidenceType.VERSION, "pom", "version", version, Confidence.HIGHEST);
            if (parentVersion != null && !parentVersion.isEmpty() && !parentVersion.equals(version)) {
                dependency.addEvidence(EvidenceType.VERSION, "pom", "parent-version", version, Confidence.LOW);
            }
        } else {
            addAsIdentifier = false;
        }

        if (addAsIdentifier && isMainPom) {
            Identifier id = null;
            try {
                if (originalArtifactID != null && originalArtifactID.matches(VALID_NAME)
                        && originalGroupID != null && originalGroupID.matches(VALID_NAME)) {
                    final PackageURL purl = PackageURLBuilder.aPackageURL().withType("maven").withNamespace(originalGroupID)
                            .withName(originalArtifactID).withVersion(version).build();
                    id = new PurlIdentifier(purl, Confidence.HIGH);
                } else {
                    LOGGER.debug("Invalid maven identifier identified: " + originalGroupID + ":" + originalArtifactID);
                }
            } catch (MalformedPackageURLException ex) {
                final String gav = String.format("%s:%s:%s", originalGroupID, originalArtifactID, version);
                LOGGER.debug("Error building package url for " + gav + "; using generic identifier instead.", ex);
                id = new GenericIdentifier("maven:" + gav, Confidence.HIGH);
            }
            if (id != null) {
                dependency.addSoftwareIdentifier(id);
            }
        }

        // org name
        final String org = pom.getOrganization();
        if (org != null && !org.isEmpty()) {
            dependency.addEvidence(EvidenceType.VENDOR, "pom", "organization name", org, Confidence.HIGH);
            dependency.addEvidence(EvidenceType.PRODUCT, "pom", "organization name", org, Confidence.LOW);
            addMatchingValues(classes, org, dependency, EvidenceType.VENDOR);
            addMatchingValues(classes, org, dependency, EvidenceType.PRODUCT);
        }
        // org name
        String orgUrl = pom.getOrganizationUrl();
        if (orgUrl != null && !orgUrl.isEmpty()) {
            if (orgUrl.startsWith("https://github.com/") || orgUrl.startsWith("https://gitlab.com/")) {
                orgUrl = orgUrl.substring(19);
                dependency.addEvidence(EvidenceType.PRODUCT, "pom", "url", orgUrl, Confidence.HIGH);
            } else {
                dependency.addEvidence(EvidenceType.PRODUCT, "pom", "organization url", orgUrl, Confidence.LOW);
            }
            dependency.addEvidence(EvidenceType.VENDOR, "pom", "organization url", orgUrl, Confidence.MEDIUM);
        }
        //pom name
        final String pomName = pom.getName();
        if (pomName != null && !pomName.isEmpty() && !"${project.groupId}:${project.artifactId}".equals(pomName)) {
            foundSomething = true;
            dependency.addEvidence(EvidenceType.PRODUCT, "pom", "name", pomName, Confidence.HIGH);
            dependency.addEvidence(EvidenceType.VENDOR, "pom", "name", pomName, Confidence.HIGH);
            addMatchingValues(classes, pomName, dependency, EvidenceType.VENDOR);
            addMatchingValues(classes, pomName, dependency, EvidenceType.PRODUCT);
        }

        //Description
        final String description = pom.getDescription();
        if (description != null && !description.isEmpty()
                && !description.startsWith("POM was created by")
                && !description.startsWith("Sonatype helps open source projects")
                && !description.endsWith("project for Spring Boot")) {
            foundSomething = true;
            final String trimmedDescription = addDescription(dependency, description, "pom", "description");
            addMatchingValues(classes, trimmedDescription, dependency, EvidenceType.VENDOR);
            addMatchingValues(classes, trimmedDescription, dependency, EvidenceType.PRODUCT);
        }

        String projectURL = pom.getProjectURL();
        if (projectURL != null && !projectURL.trim().isEmpty()) {
            if (projectURL.startsWith("https://github.com/") || projectURL.startsWith("https://gitlab.com/")) {
                projectURL = projectURL.substring(19);
                dependency.addEvidence(EvidenceType.PRODUCT, "pom", "url", projectURL, Confidence.HIGH);
            } else {
                dependency.addEvidence(EvidenceType.PRODUCT, "pom", "url", projectURL, Confidence.MEDIUM);
            }
            dependency.addEvidence(EvidenceType.VENDOR, "pom", "url", projectURL, Confidence.HIGHEST);

        }

        if (pom.getDevelopers() != null && !pom.getDevelopers().isEmpty()) {
            for (Developer dev : pom.getDevelopers()) {
                if (!Strings.isNullOrEmpty(dev.getId())) {
                    dependency.addEvidence(EvidenceType.VENDOR, "pom", "developer id", dev.getId(), Confidence.MEDIUM);
                    dependency.addEvidence(EvidenceType.PRODUCT, "pom", "developer id", dev.getId(), Confidence.LOW);
                }
                if (!Strings.isNullOrEmpty(dev.getName())) {
                    dependency.addEvidence(EvidenceType.VENDOR, "pom", "developer name", dev.getName(), Confidence.MEDIUM);
                    dependency.addEvidence(EvidenceType.PRODUCT, "pom", "developer name", dev.getName(), Confidence.LOW);
                }
                if (!Strings.isNullOrEmpty(dev.getEmail())) {
                    dependency.addEvidence(EvidenceType.VENDOR, "pom", "developer email", dev.getEmail(), Confidence.LOW);
                    dependency.addEvidence(EvidenceType.PRODUCT, "pom", "developer email", dev.getEmail(), Confidence.LOW);
                }
                if (!Strings.isNullOrEmpty(dev.getOrganizationUrl())) {
                    dependency.addEvidence(EvidenceType.VENDOR, "pom", "developer org URL", dev.getOrganizationUrl(), Confidence.MEDIUM);
                    dependency.addEvidence(EvidenceType.PRODUCT, "pom", "developer org URL", dev.getOrganizationUrl(), Confidence.LOW);
                }
                final String devOrg = dev.getOrganization();
                if (!Strings.isNullOrEmpty(devOrg)) {
                    dependency.addEvidence(EvidenceType.VENDOR, "pom", "developer org", devOrg, Confidence.MEDIUM);
                    dependency.addEvidence(EvidenceType.PRODUCT, "pom", "developer org", devOrg, Confidence.LOW);
                    addMatchingValues(classes, devOrg, dependency, EvidenceType.VENDOR);
                    addMatchingValues(classes, devOrg, dependency, EvidenceType.PRODUCT);
                }
            }
        }
//        System.out.println(dependency.getFileName());
        extractLicense(pom, dependency);
        return foundSomething;
    }

    /**
     * Analyzes the path information of the classes contained within the
     * JarAnalyzer to try and determine possible vendor or product names. If any
     * are found they are stored in the packageVendor and packageProduct
     * hashSets.
     *
     * @param classNames            a list of class names
     * @param dependency            a dependency to analyze
     * @param addPackagesAsEvidence a flag indicating whether or not package
     *                              names should be added as evidence.
     */
    protected void analyzePackageNames(List<ClassNameInformation> classNames,
                                       Dependency dependency, boolean addPackagesAsEvidence) {
        final Map<String, Integer> vendorIdentifiers = new HashMap<>();
        final Map<String, Integer> productIdentifiers = new HashMap<>();
        analyzeFullyQualifiedClassNames(classNames, vendorIdentifiers, productIdentifiers);

        final int classCount = classNames.size();

        vendorIdentifiers.forEach((key, value) -> {
            final float ratio = value / (float) classCount;
            if (ratio > 0.5) {
                //TODO remove weighting?
                dependency.addVendorWeighting(key);
                if (addPackagesAsEvidence && key.length() > 1) {
                    dependency.addEvidence(EvidenceType.VENDOR, "jar", "package name", key, Confidence.LOW);
                }
            }
        });
        productIdentifiers.forEach((key, value) -> {
            final float ratio = value / (float) classCount;
            if (ratio > 0.5) {
                //todo remove weighting
                dependency.addProductWeighting(key);
                if (addPackagesAsEvidence && key.length() > 1) {
                    dependency.addEvidence(EvidenceType.PRODUCT, "jar", "package name", key, Confidence.LOW);
                }
            }
        });
    }

    /**
     * <p>
     * Reads the manifest from the JAR file and collects the entries. Some
     * vendorKey entries are:</p>
     * <ul><li>Implementation Title</li>
     * <li>Implementation Version</li> <li>Implementation Vendor</li>
     * <li>Implementation VendorId</li> <li>Bundle Name</li> <li>Bundle
     * Version</li> <li>Bundle Vendor</li> <li>Bundle Description</li> <li>Main
     * Class</li> </ul>
     * However, all but a handful of specific entries are read in.
     *
     * @param dependency       A reference to the dependency
     * @param classInformation a collection of class information
     * @return whether evidence was identified parsing the manifest
     * @throws IOException if there is an issue reading the JAR file
     */
    //CSOFF: MethodLength
    protected boolean parseManifest(Dependency dependency, List<ClassNameInformation> classInformation)
            throws IOException {
        boolean foundSomething = false;
        try (JarFile jar = new JarFile(dependency.getActualFilePath(), false)) {
            final Manifest manifest = jar.getManifest();
            if (manifest == null) {
                if (!dependency.getFileName().toLowerCase().endsWith("-sources.jar")
                        && !dependency.getFileName().toLowerCase().endsWith("-javadoc.jar")
                        && !dependency.getFileName().toLowerCase().endsWith("-src.jar")
                        && !dependency.getFileName().toLowerCase().endsWith("-doc.jar")) {
                    LOGGER.debug("Jar file '{}' does not contain a manifest.", dependency.getFileName());
                }
                return false;
            }
            String source = "Manifest";
            String specificationVersion = null;
            boolean hasImplementationVersion = false;
            Attributes atts = manifest.getMainAttributes();
            for (Entry<Object, Object> entry : atts.entrySet()) {
                String key = entry.getKey().toString();
                String value = atts.getValue(key);
                if (HTML_DETECTION_PATTERN.matcher(value).find()) {
                    value = Jsoup.parse(value).text();
                }
                if (value.startsWith("git@github.com:") || value.startsWith("git@gitlab.com:")) {
                    value = value.substring(15);
                }
                if (IGNORE_VALUES.contains(value)) {
                    continue;
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_TITLE.toString())) {
                    foundSomething = true;
                    dependency.addEvidence(EvidenceType.PRODUCT, source, key, value, Confidence.HIGH);
                    addMatchingValues(classInformation, value, dependency, EvidenceType.PRODUCT);
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VERSION.toString())) {
                    hasImplementationVersion = true;
                    foundSomething = true;
                    dependency.addEvidence(EvidenceType.VERSION, source, key, value, Confidence.HIGH);
                } else if ("specification-version".equalsIgnoreCase(key)) {
                    specificationVersion = value;
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VENDOR.toString())) {
                    foundSomething = true;
                    dependency.addEvidence(EvidenceType.VENDOR, source, key, value, Confidence.HIGH);
                    addMatchingValues(classInformation, value, dependency, EvidenceType.VENDOR);
                } else if (key.equalsIgnoreCase(IMPLEMENTATION_VENDOR_ID)) {
                    foundSomething = true;
                    dependency.addEvidence(EvidenceType.VENDOR, source, key, value, Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, dependency, EvidenceType.VENDOR);
                } else if (key.equalsIgnoreCase(BUNDLE_DESCRIPTION)) {
                    if (!value.startsWith("Sonatype helps open source projects")) {
                        foundSomething = true;
                        addDescription(dependency, value, "manifest", key);
                        addMatchingValues(classInformation, value, dependency, EvidenceType.PRODUCT);
                    }
                } else if (key.equalsIgnoreCase(BUNDLE_NAME)) {
                    foundSomething = true;
                    dependency.addEvidence(EvidenceType.PRODUCT, source, key, value, Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, dependency, EvidenceType.PRODUCT);
//                //the following caused false positives.
//                } else if (key.equalsIgnoreCase(BUNDLE_VENDOR)) {
                } else if (key.equalsIgnoreCase(BUNDLE_VERSION)) {
                    foundSomething = true;
                    dependency.addEvidence(EvidenceType.VERSION, source, key, value, Confidence.HIGH);
                } else if (key.equalsIgnoreCase(Attributes.Name.MAIN_CLASS.toString())) {
                    //noinspection UnnecessaryContinue
                    continue;
                    //skipping main class as if this has important information to add it will be added during class name analysis...
                } else if ("implementation-url".equalsIgnoreCase(key)
                        && value != null
                        && value.startsWith("https://projects.spring.io/spring-boot/#/spring-boot-starter-parent/parent/")) {
                    continue;
                } else {
                    key = key.toLowerCase();
                    if (!IGNORE_KEYS.contains(key)
                            && !key.endsWith("jdk")
                            && !key.contains("lastmodified")
                            && !key.endsWith("package")
                            && !key.endsWith("classpath")
                            && !key.endsWith("class-path")
                            && !key.endsWith("-scm") //todo change this to a regex?
                            && !key.startsWith("scm-")
                            && !value.trim().startsWith("scm:")
                            && !isImportPackage(key, value)
                            && !isPackage(key, value)) {
                        foundSomething = true;
                        if (key.contains("version")) {
                            if (!key.contains("specification")) {
                                dependency.addEvidence(EvidenceType.VERSION, source, key, value, Confidence.MEDIUM);
                            }
                        } else if ("build-id".equals(key)) {
                            int pos = value.indexOf('(');
                            if (pos > 0) {
                                value = value.substring(0, pos - 1);
                            }
                            pos = value.indexOf('[');
                            if (pos > 0) {
                                value = value.substring(0, pos - 1);
                            }
                            dependency.addEvidence(EvidenceType.VERSION, source, key, value, Confidence.MEDIUM);
                        } else if (key.contains("title")) {
                            dependency.addEvidence(EvidenceType.PRODUCT, source, key, value, Confidence.MEDIUM);
                            addMatchingValues(classInformation, value, dependency, EvidenceType.PRODUCT);
                        } else if (key.contains("vendor")) {
                            if (key.contains("specification")) {
                                dependency.addEvidence(EvidenceType.VENDOR, source, key, value, Confidence.LOW);
                            } else {
                                dependency.addEvidence(EvidenceType.VENDOR, source, key, value, Confidence.MEDIUM);
                                addMatchingValues(classInformation, value, dependency, EvidenceType.VENDOR);
                            }
                        } else if (key.contains("name")) {
                            dependency.addEvidence(EvidenceType.PRODUCT, source, key, value, Confidence.MEDIUM);
                            dependency.addEvidence(EvidenceType.VENDOR, source, key, value, Confidence.MEDIUM);
                            addMatchingValues(classInformation, value, dependency, EvidenceType.VENDOR);
                            addMatchingValues(classInformation, value, dependency, EvidenceType.PRODUCT);
                        } else if (key.contains("license")) {
                            addLicense(dependency, value);
                        } else if (key.contains("description")) {
                            if (!value.startsWith("Sonatype helps open source projects")) {
                                final String trimmedDescription = addDescription(dependency, value, "manifest", key);
                                addMatchingValues(classInformation, trimmedDescription, dependency, EvidenceType.VENDOR);
                                addMatchingValues(classInformation, trimmedDescription, dependency, EvidenceType.PRODUCT);
                            }
                        } else {
                            dependency.addEvidence(EvidenceType.PRODUCT, source, key, value, Confidence.LOW);
                            dependency.addEvidence(EvidenceType.VENDOR, source, key, value, Confidence.LOW);
                            addMatchingValues(classInformation, value, dependency, EvidenceType.VERSION);
                            addMatchingValues(classInformation, value, dependency, EvidenceType.PRODUCT);
                            if (value.matches(".*\\d.*")) {
                                final StringTokenizer tokenizer = new StringTokenizer(value, " ");
                                while (tokenizer.hasMoreElements()) {
                                    final String s = tokenizer.nextToken();
                                    if (s.matches("^[0-9.]+$")) {
                                        dependency.addEvidence(EvidenceType.VERSION, source, key, s, Confidence.LOW);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for (Entry<String, Attributes> item : manifest.getEntries().entrySet()) {
                final String name = item.getKey();
                source = "manifest: " + name;
                atts = item.getValue();
                for (Entry<Object, Object> entry : atts.entrySet()) {
                    final String key = entry.getKey().toString();
                    final String value = atts.getValue(key);
                    if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_TITLE.toString())) {
                        foundSomething = true;
                        dependency.addEvidence(EvidenceType.PRODUCT, source, key, value, Confidence.MEDIUM);
                        addMatchingValues(classInformation, value, dependency, EvidenceType.PRODUCT);
                    } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VERSION.toString())) {
                        foundSomething = true;
                        dependency.addEvidence(EvidenceType.VERSION, source, key, value, Confidence.MEDIUM);
                    } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VENDOR.toString())) {
                        foundSomething = true;
                        dependency.addEvidence(EvidenceType.VENDOR, source, key, value, Confidence.MEDIUM);
                        addMatchingValues(classInformation, value, dependency, EvidenceType.VENDOR);
                    } else if (key.equalsIgnoreCase(Attributes.Name.SPECIFICATION_TITLE.toString())) {
                        foundSomething = true;
                        dependency.addEvidence(EvidenceType.PRODUCT, source, key, value, Confidence.MEDIUM);
                        addMatchingValues(classInformation, value, dependency, EvidenceType.PRODUCT);
                    }
                }
            }
            if (specificationVersion != null && !hasImplementationVersion) {
                foundSomething = true;
                dependency.addEvidence(EvidenceType.VERSION, source, "specification-version", specificationVersion, Confidence.HIGH);
            }
        }
        return foundSomething;
    }
    //CSON: MethodLength

    /**
     * Adds a description to the given dependency. If the description contains
     * one of the following strings beyond 100 characters, then the description
     * used will be trimmed to that position:
     * <ul><li>"such as"</li><li>"like "</li><li>"will use "</li><li>"* uses
     * "</li></ul>
     *
     * @param dependency  a dependency
     * @param description the description
     * @param source      the source of the evidence
     * @param key         the "name" of the evidence
     * @return if the description is trimmed, the trimmed version is returned;
     * otherwise the original description is returned
     */
    public static String addDescription(Dependency dependency, String description, String source, String key) {
        if (dependency.getDescription() == null) {
            dependency.setDescription(description);
        }
        String desc;
        if (HTML_DETECTION_PATTERN.matcher(description).find()) {
            desc = Jsoup.parse(description).text();
        } else {
            desc = description;
        }
        dependency.setDescription(desc);
        if (desc.length() > 100) {
            desc = desc.replaceAll("\\s\\s+", " ");
            final int posSuchAs = desc.toLowerCase().indexOf("such as ", 100);
            final int posLike = desc.toLowerCase().indexOf("like ", 100);
            final int posWillUse = desc.toLowerCase().indexOf("will use ", 100);
            final int posUses = desc.toLowerCase().indexOf(" uses ", 100);

            int pos = -1;
            pos = Math.max(pos, posSuchAs);
            if (pos >= 0 && posLike >= 0) {
                pos = Math.min(pos, posLike);
            } else {
                pos = Math.max(pos, posLike);
            }
            if (pos >= 0 && posWillUse >= 0) {
                pos = Math.min(pos, posWillUse);
            } else {
                pos = Math.max(pos, posWillUse);
            }
            if (pos >= 0 && posUses >= 0) {
                pos = Math.min(pos, posUses);
            } else {
                pos = Math.max(pos, posUses);
            }
            if (pos > 0) {
                desc = desc.substring(0, pos) + "...";
            }
//            //no longer add description directly. Use matching terms in other parts of the evidence collection
//            //but description adds too many FP
//            dependency.addEvidence(EvidenceType.PRODUCT, source, key, desc, Confidence.LOW);
//            dependency.addEvidence(EvidenceType.VENDOR, source, key, desc, Confidence.LOW);
//        } else {
//            dependency.addEvidence(EvidenceType.PRODUCT, source, key, desc, Confidence.MEDIUM);
//            dependency.addEvidence(EvidenceType.VENDOR, source, key, desc, Confidence.MEDIUM);
        }
        return desc;
    }

    /**
     * Adds a license to the given dependency.
     *
     * @param d       a dependency
     * @param license the license
     */
    private void addLicense(Dependency d, String license) {
        if (d.getLicense() == null) {
            d.setLicense(license);
        } else if (!d.getLicense().contains(license)) {
            d.setLicense(d.getLicense() + NEWLINE + license);
        }
    }

    public static boolean deleteFileOrDirectory(File file) {
        if (null != file) {

            if (!file.exists()) {
                return true;
            }

            int i;
            // file 是文件
            if (file.isFile()) {
                boolean result = file.delete();
                // 限制循环次数，避免死循环
                for (i = 0; !result && i++ < 10; result = file.delete()) {
                    // 垃圾回收
                    System.gc();
                }

                return result;
            }

            // file 是目录
            File[] files = file.listFiles();
            if (null != files) {
                for (i = 0; i < files.length; ++i) {
                    deleteFileOrDirectory(files[i]);
                }
            }

            file.delete();
        }
        return true;

    }


    /**
     * Initializes the JarAnalyzer.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException is thrown if there is an exception
     *                                 creating a temporary directory
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        try {
            final File baseDir = getSettings().getTempDirectory();
            tempFileLocation = File.createTempFile("check", "tmp", baseDir);
            if (!tempFileLocation.delete() && !deleteFileOrDirectory(tempFileLocation)
            ) {
                final String msg = String.format("Unable to delete temporary file '%s'.", tempFileLocation.getAbsolutePath());
                setEnabled(false);
                throw new InitializationException(msg);
            }
            if (!tempFileLocation.mkdirs()) {
                final String msg = String.format("Unable to create directory '%s'.", tempFileLocation.getAbsolutePath());
                setEnabled(false);
                throw new InitializationException(msg);
            }
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create a temporary file", ex);
        }
    }

    /**
     * Deletes any files extracted from the JAR during analysis.
     */
    @Override
    public void closeAnalyzer() {
        if (tempFileLocation != null && tempFileLocation.exists()) {
            LOGGER.debug("Attempting to delete temporary files from `{}`", tempFileLocation.toString());
            final boolean success = FileUtils.delete(tempFileLocation) || deleteFileOrDirectory(tempFileLocation);
            if (!success && tempFileLocation.exists()) {
                final String[] l = tempFileLocation.list();
                if (l != null && l.length > 0) {
                    LOGGER.warn("Failed to delete the JAR Analyzder's temporary files from `{}`, "
                            + "see the log for more details", tempFileLocation.getAbsolutePath());
                }
            }
        }
    }

    /**
     * Determines if the key value pair from the manifest is for an "import"
     * type entry for package names.
     *
     * @param key   the key from the manifest
     * @param value the value from the manifest
     * @return true or false depending on if it is believed the entry is an
     * "import" entry
     */
    private boolean isImportPackage(String key, String value) {
        final Pattern packageRx = Pattern.compile("^(\\s*[a-zA-Z0-9_#\\$\\*\\.]+\\s*[,;])+(\\s*[a-zA-Z0-9_#\\$\\*\\.]+\\s*)?$");
        final boolean matches = packageRx.matcher(value).matches();
        return matches && (key.contains("import") || key.contains("include") || value.length() > 10);
    }

    /**
     * Cycles through an enumeration of JarEntries, contained within the
     * dependency, and returns a list of the class names. This does not include
     * core Java package names (i.e. java.* or javax.*).
     *
     * @param dependency the dependency being analyzed
     * @return an list of fully qualified class names
     */
    protected List<ClassNameInformation> collectClassNames(Dependency dependency) {
        final List<ClassNameInformation> classNames = new ArrayList<>();
        try (JarFile jar = new JarFile(dependency.getActualFilePath(), false)) {
            final Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                final JarEntry entry = entries.nextElement();
                final String name = entry.getName().toLowerCase();
                //no longer stripping "|com\\.sun" - there are some com.sun jar files with CVEs.
                if (name.endsWith(".class") && !name.matches("^javax?\\..*$")) {
                    final ClassNameInformation className = new ClassNameInformation(name.substring(0, name.length() - 6));
                    classNames.add(className);
                }
            }
        } catch (IOException ex) {
            LOGGER.warn("Unable to open jar file '{}'.", dependency.getFileName());
            LOGGER.debug("", ex);
        }
        return classNames;
    }

    /**
     * Cycles through the list of class names and places the package levels 0-3
     * into the provided maps for vendor and product. This is helpful when
     * analyzing vendor/product as many times this is included in the package
     * name.
     *
     * @param classNames a list of class names
     * @param vendor     HashMap of possible vendor names from package names (e.g.
     *                   owasp)
     * @param product    HashMap of possible product names from package names (e.g.
     *                   dependencycheck)
     */
    private void analyzeFullyQualifiedClassNames(List<ClassNameInformation> classNames,
                                                 Map<String, Integer> vendor, Map<String, Integer> product) {
        for (ClassNameInformation entry : classNames) {
            final List<String> list = entry.getPackageStructure();
            addEntry(vendor, list.get(0));

            if (list.size() == 2) {
                addEntry(product, list.get(1));
            } else if (list.size() == 3) {
                addEntry(vendor, list.get(1));
                addEntry(product, list.get(1));
                addEntry(product, list.get(2));
            } else if (list.size() >= 4) {
                addEntry(vendor, list.get(1));
                addEntry(vendor, list.get(2));
                addEntry(product, list.get(1));
                addEntry(product, list.get(2));
                addEntry(product, list.get(3));
            }
        }
    }

    /**
     * Adds an entry to the specified collection and sets the Integer (e.g. the
     * count) to 1. If the entry already exists in the collection then the
     * Integer is incremented by 1.
     *
     * @param collection a collection of strings and their occurrence count
     * @param key        the key to add to the collection
     */
    private void addEntry(Map<String, Integer> collection, String key) {
        if (collection.containsKey(key)) {
            collection.put(key, collection.get(key) + 1);
        } else {
            collection.put(key, 1);
        }
    }

    /**
     * Cycles through the collection of class name information to see if parts
     * of the package names are contained in the provided value. If found, it
     * will be added as the HIGHEST confidence evidence because we have more
     * then one source corroborating the value.
     *
     * @param classes a collection of class name information
     * @param value   the value to check to see if it contains a package name
     * @param dep     the dependency to add new entries too
     * @param type    the type of evidence (vendor, product, or version)
     */
    protected static void addMatchingValues(List<ClassNameInformation> classes, String value, Dependency dep, EvidenceType type) {
        if (value == null || value.isEmpty() || classes == null || classes.isEmpty()) {
            return;
        }
        final HashSet<String> tested = new HashSet<>();
        //TODO add a hashSet and only analyze any given key once.
        for (ClassNameInformation cni : classes) {
            //classes.forEach((cni) -> {
            for (String key : cni.getPackageStructure()) {
                //cni.getPackageStructure().forEach((key) -> {
                if (!tested.contains(key)) {
                    tested.add(key);
                    final int pos = StringUtils.indexOfIgnoreCase(value, key);
                    if ((pos == 0 && (key.length() == value.length() || (key.length() < value.length()
                            && !Character.isLetterOrDigit(value.charAt(key.length())))))
                            || (pos > 0 && !Character.isLetterOrDigit(value.charAt(pos - 1))
                            && (pos + key.length() == value.length() || (key.length() < value.length()
                            && !Character.isLetterOrDigit(value.charAt(pos + key.length())))))) {
                        dep.addEvidence(type, "jar", "package name", key, Confidence.HIGHEST);
                    }
                }
            }
        }
    }

    /**
     * Simple check to see if the attribute from a manifest is just a package
     * name.
     *
     * @param key   the key of the value to check
     * @param value the value to check
     * @return true if the value looks like a java package name, otherwise false
     */
    private boolean isPackage(String key, String value) {

        return !key.matches(".*(version|title|vendor|name|license|description).*")
                && value.matches("^[a-zA-Z_][a-zA-Z0-9_\\$]*\\.([a-zA-Z_][a-zA-Z0-9_\\$]*\\.)*([a-zA-Z_][a-zA-Z0-9_\\$]*)$");

    }

    /**
     * Extracts the license information from the pom and adds it to the
     * dependency.
     *
     * @param pom        the pom object
     * @param dependency the dependency to add license information too
     */
    public static void extractLicense(Model pom, Dependency dependency) {
        //license
        if (pom.getLicenses() != null) {
            StringBuilder license = null;
            for (License lic : pom.getLicenses()) {
                String tmp = null;
                if (lic.getName() != null) {
                    tmp = lic.getName();
                }
                if (lic.getUrl() != null) {
                    if (tmp == null) {
                        tmp = lic.getUrl();
                    } else {
                        tmp += ": " + lic.getUrl();
                    }
                }
                if (tmp == null) {
                    continue;
                }
                if (HTML_DETECTION_PATTERN.matcher(tmp).find()) {
                    tmp = Jsoup.parse(tmp).text();
                }
                if (license == null) {
                    license = new StringBuilder(tmp);
                } else {
                    license.append("\n").append(tmp);
                }
            }
            if (license != null) {
                dependency.setLicense(license.toString());

            }
        }
    }


    /**
     * Stores information about a class name.
     */
    protected static class ClassNameInformation {

        /**
         * The fully qualified class name.
         */
        private String name;
        /**
         * Up to the first four levels of the package structure, excluding a
         * leading "org" or "com".
         */
        private final ArrayList<String> packageStructure = new ArrayList<>();

        /**
         * <p>
         * Stores information about a given class name. This class will keep the
         * fully qualified class name and a list of the important parts of the
         * package structure. Up to the first four levels of the package
         * structure are stored, excluding a leading "org" or "com".
         * Example:</p>
         * <code>ClassNameInformation obj = new ClassNameInformation("org/owasp/dependencycheck/analyzer/JarAnalyzer");
         * System.out.println(obj.getName());
         * for (String p : obj.getPackageStructure())
         * System.out.println(p);
         * </code>
         * <p>
         * Would result in:</p>
         * <code>zju.cst.aces.dependencycheck.analyzer.JarAnalyzer
         * owasp
         * dependencycheck
         * analyzer
         * jaranalyzer</code>
         *
         * @param className a fully qualified class name
         */
        ClassNameInformation(String className) {
            name = className;
            if (name.contains("/")) {
                final String[] tmp = StringUtils.split(className.toLowerCase(), '/');
                int start = 0;
                int end = 3;
                if ("com".equals(tmp[0]) || "org".equals(tmp[0])) {
                    start = 1;
                    end = 4;
                }
                if (tmp.length <= end) {
                    end = tmp.length - 1;
                }
                packageStructure.addAll(Arrays.asList(tmp).subList(start, end + 1));
            } else {
                packageStructure.add(name);
            }
        }

        /**
         * Get the value of name
         *
         * @return the value of name
         */
        public String getName() {
            return name;
        }

        /**
         * Set the value of name
         *
         * @param name new value of name
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * Get the value of packageStructure
         *
         * @return the value of packageStructure
         */
        public ArrayList<String> getPackageStructure() {
            return packageStructure;
        }
    }

    /**
     * Retrieves the next temporary directory to extract an archive too.
     *
     * @return a directory
     * @throws AnalysisException thrown if unable to create temporary directory
     */
    private File getNextTempDirectory() throws AnalysisException {
        final int dirCount = DIR_COUNT.incrementAndGet();
        final File directory = new File(tempFileLocation, String.valueOf(dirCount));
        //getting an exception for some directories not being able to be created; might be because the directory already exists?
        if (directory.exists()) {
            return getNextTempDirectory();
//            return directory;
        }
        if (!directory.mkdirs()) {
            final String msg = String.format("Unable to create temp directory '%s'.", directory.getAbsolutePath());
            throw new AnalysisException(msg);
        }
        return directory;
    }
}
