package zju.cst.aces.dependencycheck.analyzer;


import com.alibaba.fastjson2.JSONObject;
import fj.Hash;
import zju.cst.aces.dependencycheck.Engine;
import zju.cst.aces.dependencycheck.dependency.Dependency;
import zju.cst.aces.dependencycheck.dependency.naming.CVE;
import zju.cst.aces.dependencycheck.dependency.naming.CVEFilesItem;
import zju.cst.aces.dependencycheck.dependency.naming.CVEFunctionsItem;
import zju.cst.aces.dependencycheck.dependency.naming.CVEPatchesItem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;


public class CveAnalyzer extends AbstractAnalyzer {

    public static String CveFilesDir = "";

    public static String filepath = "D:\\java\\json\\CVE-2020-8908_meta.json";
    public static List<String> result = new ArrayList<>();


    // TODO: 2023/7/24 Init and Update CVD DataBase
    public static void initAndUpdate() {

    }

    public static HashMap<CVE, List<String>> doCveAnalysis(String groupid, String artifactid, String version) {
        initAndUpdate();
        detectCve(groupid, artifactid, version);

    }

//    public static void main(String[] args) {
//        String groupid = "com.google";
//        String artifactid = "guava", version = "1";
//        System.out.println(readCve(groupid,artifactid,version,"D:\\java\\json\\CVE-2020-8908_meta.json"));
//    }

    /*
     * Get Attributes from CVE
     *
     * */
    public static HashMap<CVE, List<String>> detectCve(String groupid, String artifactid, String version) {

        String regxAll = artifactid + ":*";
        String regxSingle = artifactid + ":" + version;
        try {
            CVE cve = JSONObject.parseObject(Files.readString(Path.of(filepath)),
                    CVE.class);
            List<String> cpelist = cve.getCpes();
            List<CVEPatchesItem> cvePatchesItems = cve.getPatches();
            String first_path = cvePatchesItems.get(0).getFiles().get(0).getPath();

            //Only Java projects
            if (!first_path.contains("java"))
                return null;


            for (String cpe : cpelist
            ) {

                // TODO: 2023/7/24 CPE < version
                if (cpe.matches(regxAll) || cpe.matches(regxSingle)) {
                    System.out.println(cpe);

                    // use artifactid find the correct patch
                    //  use groupid find owner
                    List<CVEFilesItem> cveFilesItems = cvePatchesItems.stream().filter(cvePatchesItem -> cvePatchesItem.getRepo().equals(artifactid) && groupid.contains(cvePatchesItem.getOwner())).flatMap(cvePatchesItem -> cvePatchesItem.getFiles().stream()).collect(Collectors.toList());
                    List<CVEFunctionsItem> cveFunctionsItems = cveFilesItems.stream().flatMap(cveFilesItem -> cveFilesItem.getFunctions().stream()).collect(Collectors.toList());

                    List<String> paths = cveFilesItems.stream()
                            .map(CVEFilesItem::getPath).collect(Collectors.toList());
                    //Singel function Name  No stream No flatMap
                    List<String> functionNames = cveFunctionsItems.stream().map(CVEFunctionsItem::getfunction_name).collect(Collectors.toList());
                    for (int i = 0; i < paths.size(); i++) {
                        String path = paths.get(i);
                        String fn = functionNames.get(i);
                        result.add(path.substring(path.indexOf("src/") + 4, path.length() - 5) + "." + fn.substring(fn.lastIndexOf(" ") + 1, fn.length() - 2));
                        System.out.println(result);
                    }

                }

            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
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
}
