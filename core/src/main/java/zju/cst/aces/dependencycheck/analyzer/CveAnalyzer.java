package zju.cst.aces.dependencycheck.analyzer;


import com.alibaba.fastjson2.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import zju.cst.aces.dependencycheck.Engine;
import zju.cst.aces.dependencycheck.dependency.Dependency;
import zju.cst.aces.dependencycheck.dependency.naming.CVE;
import zju.cst.aces.dependencycheck.dependency.naming.CVEFilesItem;
import zju.cst.aces.dependencycheck.dependency.naming.CVEFunctionsItem;
import zju.cst.aces.dependencycheck.dependency.naming.CVEPatchesItem;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;


public class CveAnalyzer extends AbstractAnalyzer {


    private static final Logger LOGGER = LoggerFactory.getLogger(CveAnalyzer.class);

    public static String CveFilesDir = System.getProperty("user.dir")+"/json/";
    public static List<String> list = new ArrayList<>();


    // TODO: 2023/7/25 Parse Json file and insert into db
    // TODO: 2023/7/24 Init and Update CVD DataBase
    public static boolean initAndUpdate() {
        if (CveFilesDir == "") return false;
        List<String> list = Arrays.asList(new File(CveFilesDir).list());
        return true;
    }


//    public  static void main(String[] args) {
//        String groupid = "com.google";
//        String artifactid = "guava", version = "1";
//        Dependency dependency = new Dependency();
//        dependency.Groupname = groupid;
//        dependency.artifactid =artifactid;
//        dependency.setVersion(version);
//        System.out.println(detectCve(dependency));
//        // 创建一个JsonFilter对象，用于过滤json文件
//
//
//    }

    /*
     * Get Attributes from CVE
     *
     * */
    public static List<String> detectCve(Dependency dependency) {
        List<String> vul_funcs = new ArrayList<>();

        String regxAll = dependency.artifactid + ":*";
        HashMap<Dependency, List<String>> dep_vulFunc = new HashMap<>();
        try {
            JsonFilter filter = new JsonFilter();
            File dir = new File(CveFilesDir);
            String[] jsonFiles = dir.list(filter);
//            for (String filename: jsonFiles
//                 ) {

//                System.out.println(filepath);
                CVE cve = JSONObject.parseObject(new String(Files.readAllBytes(Paths.get("CVE-2020-8908_meta.json"))),
                        CVE.class);
                List<String> cpelist = cve.getCpes();
                List<CVEPatchesItem> cvePatchesItems = cve.getPatches();
                String first_path = cvePatchesItems.get(0).getFiles().get(0).getPath();

                //Only Java projects
                if (!first_path.contains("java"))
                    return null;


                for (String cpe : cpelist
                ) {

                    if (cpe.indexOf(dependency.artifactid) == -1)
                        continue;
                    // TODO: 2023/7/24 CPE < version
                    String sub_cpe = cpe.substring(cpe.indexOf(dependency.artifactid) + dependency.artifactid.length() + 1);
                    if (cpe.contains(regxAll) || (sub_cpe != null && sub_cpe.compareTo(dependency.getVersion()) >= 0)) {

                        // use artifactid find the correct patch
                        //  use groupid find owner
                        List<CVEFilesItem> cveFilesItems = cvePatchesItems.stream().filter(cvePatchesItem -> cvePatchesItem.getRepo().equals(dependency.artifactid) && dependency.Groupname.contains(cvePatchesItem.getOwner())).flatMap(cvePatchesItem -> cvePatchesItem.getFiles().stream()).collect(Collectors.toList());
                        List<CVEFunctionsItem> cveFunctionsItems = cveFilesItems.stream().flatMap(cveFilesItem -> cveFilesItem.getFunctions().stream()).collect(Collectors.toList());

                        List<String> paths = cveFilesItems.stream()
                                .map(CVEFilesItem::getPath).collect(Collectors.toList());

                        //Single function Name  No stream No flatMap
                        List<String> functionNames = cveFunctionsItems.stream().map(CVEFunctionsItem::getfunction_name).collect(Collectors.toList());
                        for (int i = 0; i < paths.size(); i++) {
                            String path = paths.get(i);
                            String fn = functionNames.get(i);
                            vul_funcs.add(path.substring(path.indexOf("src/") + 4, path.length() - 5) + "_" + fn.substring(fn.lastIndexOf(" ") + 1, fn.length() - 2));
                        }
                        dep_vulFunc.put(dependency, vul_funcs);

                    }

                }
//            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        return vul_funcs;
    }


    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) {

    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return null;
    }

    @Override
    public String getName() {
        return "Cve Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return null;
    }

    static class JsonFilter implements FilenameFilter {
        // 重写accept方法，判断文件名是否以.json结尾
        public boolean accept(File dir, String name) {
            return name.endsWith(".json")&&name.startsWith("CVE");
        }
    }
}
